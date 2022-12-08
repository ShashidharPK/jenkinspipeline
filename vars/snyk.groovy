def call(String repoUrl, String severity, String org, String proj, String failonissue, String repository, String tag, String dockerfile, String scaAnalysis, Map optional) {
	String environment = optional.environment ? "${optional.environment}" : ""
	String lifecycle = optional.lifecycle ? "${optional.lifecycle}" : ""
	String criticality = optional. criticality ? "${optional.criticality}" : ""
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
        stage('executeScaAnalysis') {
		when {
			expression { ${scaAnalysis} == 'true' }
		}
            catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                    sh """
                        set +e                        
                        snyk auth ${TOKEN}
                        snyk test --org=${org} --project-name=${proj} --remote-repo-url=${repoUrl} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${criticality}                    
                        """
                        }
                    }
                }        
       stage('executeIacAnalysis') {
            steps {
                catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                    sh """
                        set +e                        
                        snyk auth ${TOKEN}
                        snyk iac test --report                        
                        """
                        }
                    }
                }            
			}
        stage('executeSastAnalysis') {
            steps {
                catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                    sh '''
                        set +e
                        snyk auth ${TOKEN}
                        snyk code test
                        '''
                        }
                    }
                }            
	    }
        stage('executeContainerAnalysis'){
            steps {
                catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                            sh """
                                set +e
                                snyk auth ${TOKEN}
                                snyk config set disableSuggestions=true
                                snyk container test ${repository}:${tag} --file=${dockerfile}                                
                            	"""
                        }
                    }
                }
            }
        }
    }
}
