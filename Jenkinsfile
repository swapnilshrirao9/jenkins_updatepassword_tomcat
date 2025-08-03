pipeline {
    agent any
    environment {
        Jenkins_host = 'http://192.168.1.104'
        
    }

    stages {
        stage('Update Tomcat & Jenkins Credentials') {
            agent { label 'python2-agent' }
            steps {
               withCredentials([
                    usernamePassword(credentialsId: '', usernameVariable: 'NEXUS_USERNAME', passwordVariable: 'NEXUS_PASSWORD'),
                    usernamePassword(credentialsId: 'tomcat-credentials', usernameVariable: 'TOMCAT_USERNAME', passwordVariable: 'TOMCAT_PASSWORD')
                ]) { 
                script {
                        // Update Jenkins credentials
                        sh 'chmod +x ./script.py'
                // sh 'pip install paramiko requests'
                        sh "python ./script.py ${Jenkins_host} ${USERNAME_Jenkins} ${PASSWORD_Jenkins} ${Jenkins_host} ${TOMCAT_USERNAME} ${TOMCAT_PASSWORD}"
                    }
                }
            }
        }
    }
}
