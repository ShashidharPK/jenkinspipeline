def call(String repoUrl, String severity, String org, String proj, String environment, String lifecycle, String criticality, String failonissue) {
	pipeline {
    agent any

    stages {
        stage('Checkout Repo') {
            steps {
                checkout([$class: 'GitSCM', branches: [[name: '*/master']], extensions: [], userRemoteConfigs: [[credentialsId: '49174964-c138-49e8-bb2d-5daaab4ba293', url: "${repoUrl}"]]])
            }
        }
        stage('Install Dependencies') {
            steps {                
                sh 'npm install'
            }
        }
        stage('Run Snyk') {
            steps {
		    snykSecurity  (
                    additionalArguments: "--remote-repo-url=${repoUrl} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${criticality}",
                    severity: "${severity}",
		    failOnIssues: "${failonissue}",
                    organisation: "${org}",
                    projectName: "${proj}",
                    snykInstallation: 'snyk', 
                    snykTokenId: 'snyk-api-token'
                )                    
			}
        }
        stage('IAC Scan') {
            steps {
		    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    	withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                    	sh '''
                        	set +e
                        	snyk auth ${TOKEN}
                        	find . -type f -name '*.tf' | xargs snyk iac test
                        	'''
                    		}
		    }
                }            
			}
        }
	}
}
