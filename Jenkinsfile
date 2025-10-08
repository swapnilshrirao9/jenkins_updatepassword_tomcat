pipeline {
    agent { label 'python-agent' }
    parameters {
        string(name: 'USERNAME', description: 'Enter username for Basic Auth')
        string(name: 'CREDENTIAL_ID', description: 'Enter Jenkins Credential ID to create')
    }

    environment {
        JENKINS_URL = 'http://awx.local.com:8080'
        JENKINS_USER = 'admin'
    }

    stages {
        stage('Generate Base64 Auth') {
            steps {
                script {
                    // Run Python script and parse JSON output
                    def result = sh(
                        script: """python3 generate_auth.py""",
                        returnStdout: true
                    ).trim()

                    // Parse JSON into a map
                    def authData = readJSON text: result
                    env.USERNAME = authData.username
                    env.GENERATED_PASSWORD = authData.password
                    env.AUTH_B64 = authData.auth_base64

                    echo "✅ Generated Password: ${env.GENERATED_PASSWORD}"
                    echo "✅ Base64 Auth: ${env.AUTH_B64}"
                }
            }
        }

        stage('Push Credentials to Jenkins') {
            steps {
                withCredentials([string(credentialsId: 'for_jenkinscredentials', variable: 'JENKINS_API_TOKEN')]) {
                    sh '''
                        echo "🔑 Fetching Jenkins crumb..."
                        CRUMB=$(curl -s -u "$JENKINS_USER:$JENKINS_API_TOKEN" "$JENKINS_URL/crumbIssuer/api/json" | jq -r '.crumbRequestField + ":" + .crumb')

                        echo "🚀 Creating credential ID: ${CREDENTIAL_ID}"

                        curl -s -X POST "$JENKINS_URL/credentials/store/system/domain/_/createCredentials" \
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
                                "description": "Auto-created via Jenkins Pipeline",
                                "$class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"
                            }
                          }'

                        echo "✅ Credentials ${CREDENTIAL_ID} added to Jenkins."
                    '''
                }
            }
        }
    }

    post {
        success {
            echo "✅ Pipeline completed successfully!"
        }
        failure {
            echo "❌ Something went wrong."
        }
    }
}
