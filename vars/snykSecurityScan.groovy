
def snykSecurityScan (parameters) {
	
	pipeline {
    agent any

    stages {
        stage('Checkout Repo') {
            steps {
                checkout([$class: 'GitSCM', branches: [[name: '*/master']], extensions: [], userRemoteConfigs: [[credentialsId: '49174964-c138-49e8-bb2d-5daaab4ba293', url: "${parameters.repoUrl}"]]])
            }
        }
        stage('Install Dependencies') {
            steps {                
                sh 'npm install'
            }
        }
        stage('executeScaAnalysis') {
		when {
			expression { parameters.scaAnalysis == 'true'}
		}
		steps {
            		catchError(buildResult: 'SUCCESS')  {
                    	withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                    	sh """
                        	set +e                        
                        	snyk auth ${TOKEN}
                        	snyk test --org=${parameters.org} --project-name=${parameters.proj} --remote-repo-url=${parameters.repoUrl} --project-environment=${parameters.environment} --project-lifecycle=${parameters.lifecycle} --project-business-criticality=${parameters.criticality}                    
                        	"""
                        	}
                    	}
                }
	}
       stage('executeIacAnalysis') {
	       when {
			expression { parameters.iacAnalysis == 'true' }
		}
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
		when {
			expression { parameters.sastAnalysis == 'true' }
		}
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
		when {
			expression { parameters.containerAnalysis == 'true' }
		}
            steps {
                catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                            sh """
                                set +e
                                snyk auth ${TOKEN}
                                snyk config set disableSuggestions=true
                                snyk container test ${parameters.repository}:${parameters.tag}                               
                            	"""
                        }
                    }
                }
            }
        }
    }
}
