pipeline {
    agent any

    stages {
        stage('Update Tomcat & Jenkins Credentials') {
            steps {
                sh 'chmod +x ./script.py'
                sh 'pip install paramiko'
                sh 'python3 ./script.py'
            }
        }
    }
}
