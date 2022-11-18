def call(String repoUrl, string severity, string org, string proj, string environment, string lifecycle, string criticality) {
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
                echo env.WORKSPACE
                sh 'npm install'
            }
        }
        stage('Run Snyk') {
            steps {
					snykSecurity  (
                    additionalArguments: "--remote-repo-url=${repoUrl} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${criticality}",
                    severity: "${severity}", 
                    organisation: "${org}",
                    projectName: "${proj}",
                    snykInstallation: 'snyk', 
                    snykTokenId: 'snyk-api-token'
                    )                    
				}
			}
        }
	}
}
