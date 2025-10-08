pipeline {
    agent { label 'python-agent' }
    parameters {
        string(name: 'USERNAME', description: 'Enter username for Basic Auth')
    }
    stages {
        stage('Generate & Save Credentials') {
            steps {
                withCredentials([string(credentialsId: 'for_jenkinscredentials', variable: 'JENKINS_API_TOKEN')]) {
                    sh '''
                        export JENKINS_URL="http://awx.local.com:8080"
                        export JENKINS_USER="admin"
                        export JENKINS_API_TOKEN="$JENKINS_API_TOKEN"
                        export INPUT_USERNAME="${USERNAME}"
                        python3 generate_and_save_credentials.py
                    '''
                }
            }
        }
    }
}