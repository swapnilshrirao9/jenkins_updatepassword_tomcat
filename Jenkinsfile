pipeline {
    agent any

    stages {
        stage('Update Tomcat & Jenkins Credentials') {
            agent 
            steps {
                node{${python-agent}}
                sh 'python3 ./script.py'
            }
        }
    }
}
