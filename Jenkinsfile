pipeline {
    agent any

    stages {
        stage('Update Tomcat & Jenkins Credentials') {
            agent { label 'python-agent' }
            steps {
                sh 'chmod +x ./script.py'
                sh 'pip install paramiko requests'
                sh 'python3 ./script.py'
            }
        }
    }
}
