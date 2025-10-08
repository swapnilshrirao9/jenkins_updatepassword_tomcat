pipeline {
    agent any

    parameters {
        string(name: 'USERNAME', description: 'Enter the Jenkins credential username')
        string(name: 'CREDENTIAL_ID', description: 'Enter existing Jenkins Credential ID to update')
    }

    environment {
        JENKINS_URL = 'http://awx.local.com:8080'
        JENKINS_USER = 'admin'
        // ⚠️ Replace with your real Jenkins API token credential ID
        API_TOKEN_CRED_ID = 'jenkins-api-token'
    }

    stages {

        stage('Generate Base64 Password') {
            steps {
                script {
                    def result = sh(
                        script: "python generate_password.py ${params.USERNAME}",
                        returnStdout: true
                    ).trim()
                    env.GENERATED_PASSWORD = result
                    echo "🔐 Generated password: ${result}"
                }
            }
        }

        stage('Update Jenkins Credential Password') {
            steps {
                withCredentials([string(credentialsId: "${env.API_TOKEN_CRED_ID}", variable: 'JENKINS_API_TOKEN')]) {
                    sh '''
                        echo "🔑 Fetching Jenkins crumb..."
                        CRUMB=$(curl -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/crumbIssuer/api/json" | jq -r '.crumbRequestField + ":" + .crumb')

                        echo "⚙️ Updating existing credential ${CREDENTIAL_ID}..."
                        RESPONSE=$(curl -s -o /tmp/update_resp.txt -w "%{http_code}" -X POST "$JENKINS_URL/credentials/store/system/domain/_/credential/${CREDENTIAL_ID}/updateSubmit" \
                          -u "$JENKINS_USER:$JENKINS_API_TOKEN" \
                          -H "Content-Type: application/x-www-form-urlencoded" \
                          -H "$CRUMB" \
                          --data-urlencode 'json={
                            "": "0",
                            "credentials": {
                                "scope": "GLOBAL",
                                "id": "'"${CREDENTIAL_ID}"'",
                                "username": "'"${USERNAME}"'",
                                "password": "'"${GENERATED_PASSWORD}"'",
                                "description": "Updated automatically via Jenkins Pipeline",
                                "$class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"
                            }
                          }')

                        if [ "$RESPONSE" = "200" ]; then
                            echo "✅ Credential ${CREDENTIAL_ID} updated successfully."
                        else
                            echo "❌ Failed to update credential. HTTP status: $RESPONSE"
                            echo "Response body:"
                            cat /tmp/update_resp.txt
                            exit 1
                        fi
                    '''
                }
            }
        }
    }
}

