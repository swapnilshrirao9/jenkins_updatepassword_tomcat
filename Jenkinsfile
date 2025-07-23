pipeline {
    agent any

    stages {
        stage('Update Tomcat & Jenkins Credentials') {
            agent 
            steps {
                sh 'chmod +x ./script.py'
                sh 'python3 ./script.py'
            }
        }
    }
}
