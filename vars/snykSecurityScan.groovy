
def snykSecurityScan (parameters) {

    def repoUrl = parameters["repoUrl"]
    def severity = parameters["severity"]
    def org = parameters["org"]
    def proj = parameters["proj"]
    def failonissue = parameters["failonissue"]
    def repository = parameters["repository"]
    def tag = parameters["tag"]
    def scaAnalysis = parameters["scaAnalysis"]
    def iacAnalysis = parameters["iacAnalysis"]
    def sastAnalysis = parameters["sastAnalysis"]
    def containerAnalysis = parameters["containerAnalysis"]
    def environment = parameters["environment"]
    def lifecycle = parameters["lifecycle"]
    def criticality = parameters["criticality"]
	
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
			expression { scaAnalysis == 'true'}
		}
		steps {
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
	}
       stage('executeIacAnalysis') {
	       when {
			expression { iacAnalysis == 'true' }
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
			expression { sastAnalysis == 'true' }
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
			expression { containerAnalysis == 'true' }
		}
            steps {
                catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                            sh """
                                set +e
                                snyk auth ${TOKEN}
                                snyk config set disableSuggestions=true
                                snyk container test ${repository}:${tag}                               
                            	"""
                        }
                    }
                }
            }
        }
    }
}
