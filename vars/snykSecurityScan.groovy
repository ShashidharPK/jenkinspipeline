def snykSecurityScan (snykConfig) {

    String repoUrl = snykConfig.repoUrl
    String severity = snykConfig.severity
    String org = snykConfig.org
    String proj = snykConfig.proj
    String failonissue = snykConfig.failonissue
    String repository = snykConfig.repository
    String tag = snykConfig.tag
    String scaAnalysis = snykConfig.scaAnalysis
    String iacAnalysis = snykConfig.iacAnalysis
    String sastAnalysis = snykConfig.sastAnalysis
    String containerAnalysis = snykConfig.containerAnalysis
    String environment = snykConfig.environment ? "${snykConfig.environment}" : ""
    String lifecycle = snykConfig.lifecycle ? "${snykConfig.lifecycle}" : ""
    String criticality = snykConfig.criticality ? "${snykConfig.criticality}" : ""


	
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
