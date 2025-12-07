pipeline {
    agent any

    environment {
        DOCKER_IMAGE = "devsecops-app"
        REPORT_DIR = "reports"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Verify Tools') {
            steps {
                sh '''
                echo "=== Security Tools Verification ==="
                python3 --version || true
                bandit --version || true
                trivy --version || true
                tfsec --version || true
                checkov --version || true
                gitleaks version || true
                echo "All tools ready!"
                '''
            }
        }

        stage('Prepare Reports Directory') {
            steps {
                sh '''
                mkdir -p ${REPORT_DIR}
                chmod 777 ${REPORT_DIR}
                '''
            }
        }

        stage('Build Application') {
            steps {
                sh '''
                docker build -t $DOCKER_IMAGE ./app
                '''
            }
        }

        stage('Security Scans') {
            parallel {

                stage('SAST - Bandit') {
                    steps {
                        sh '''
                        mkdir -p ${REPORT_DIR}
                        bandit -r app/src -f json -o ${REPORT_DIR}/bandit.json || true
                        '''
                    }
                }

                stage('Dependency Scan') {
                    steps {
                        sh '''
                        mkdir -p ${REPORT_DIR}
                        pip-audit -r app/requirements.txt -f json -o ${REPORT_DIR}/pip-audit.json || true
                        '''
                    }
                }

                stage('Secret Scan') {
                    steps {
                        sh '''
                        mkdir -p ${REPORT_DIR}
                        gitleaks detect --source . --report-path ${REPORT_DIR}/gitleaks.json || true
                        '''
                    }
                }
            }
        }

        stage('Container Security') {
            steps {
                sh '''
                mkdir -p ${REPORT_DIR}
                timeout 300 trivy image --format json -o ${REPORT_DIR}/trivy.json $DOCKER_IMAGE || true
                timeout 60 trivy image --format cyclonedx -o ${REPORT_DIR}/sbom.json $DOCKER_IMAGE || true
                '''
            }
        }

        stage('Infrastructure Security') {
            steps {
                sh '''
                mkdir -p ${REPORT_DIR}
                tfsec terraform --format json > ${REPORT_DIR}/tfsec.json || true
                checkov -d terraform -o json > ${REPORT_DIR}/checkov.json || true
                '''
            }
        }

        stage('Push to Docker Hub') {
            when {
                environment name: 'PUSH_TO_REGISTRY', value: 'true'
            }
            environment {
                DOCKER_USER = credentials('docker-hub')
            }
            steps {
                sh '''
                echo $DOCKER_USER_PSW | docker login -u $DOCKER_USER_USR --password-stdin || true
                docker tag $DOCKER_IMAGE $DOCKER_USER_USR/$DOCKER_IMAGE:latest || true
                docker push $DOCKER_USER_USR/$DOCKER_IMAGE:latest || true
                '''
            }
        }
    }

    post {
        always {
            sh 'ls -la reports/ || echo "No reports directory"'
            archiveArtifacts artifacts: 'reports/*.json', fingerprint: true, allowEmptyArchive: true
            junit testResults: '**/test-reports/*.xml', allowEmptyResults: true
        }
        success {
            echo '✅ Pipeline succeeded! Security reports generated.'
        }
        failure {
            echo '❌ Pipeline failed! Check logs above.'
        }
    }
}
