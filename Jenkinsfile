pipeline {
    agent any
    parameters {
        string(name: 'USERNAME_credential_update', description: 'Enter the Jenkins credential username')
        string(name: 'CREDENTIAL_ID', description: 'Enter existing Jenkins Credential ID to update')
    }
    environment {
        JENKINS_URL = 'http://182.12.0.12:8080'
        JENKINS_USER = 'admin'
        // ⚠️ Replace with your real Jenkins API token credential ID
        API_TOKEN_CRED_ID = 'for_jenkinscredentials'
    }
    stages {
        stage('Generate Base64 Password') {
            steps {
                script {
                    def result = sh(
                        script: "python generate_auth.py ${params.USERNAME_credential_update}",
                        returnStdout: true
                    ).trim()
                    env.GENERATED_PASSWORD = result
                    echo " Generated password: ${result}"
                    echo "GENERATED_PASSWORD: ${env.GENERATED_PASSWORD }"
                }
            }
        }
        stage('check variable value'){
            steps {
                echo "print password: ${env.GENERATED_PASSWORD }"
            }
        }
        stage('Update Jenkins Credential Password') {
            steps {
                withCredentials([usernamePassword(credentialsId: "for_jenkinscredentials", usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                    withEnv(["GENERATED_PASSWORD=${env.GENERATED_PASSWORD}"]) {
                        sh '''
                        #!/bin/bash
                        echo "password: $GENERATED_PASSWORD"
                        CRUMB=$(curl -s -u "${USERNAME}:${PASSWORD}" "$JENKINS_URL/crumbIssuer/api/json" | jq -r '.crumbRequestField + ":" + .crumb')
                        echo "crumb=$CRUMB"
                        curl -X POST "$JENKINS_URL/credentials/store/system/domain/_/credential/User_test/config.xml" \
                          --user "${USERNAME}:${PASSWORD}" \
                          -H "$CRUMB" \
                          -H "Content-Type: application/xml" \
                          --data-raw "<com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
                            <scope>GLOBAL</scope>
                            <id>User_test</id>
                            <description>Updated credential</description>
                            <username>swapnil</username>
                            <password>$GENERATED_PASSWORD</password>
                          </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>"
                        '''
                    }
                }
            }
        }
    }
}
