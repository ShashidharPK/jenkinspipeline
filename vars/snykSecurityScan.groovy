def call(Map snykConfig) {

    String repoUrl = snykConfig.repoUrl
    String severity = snykConfig.severity
    String orgId = snykConfig.orgId
    String projectName = snykConfig.projectName    
    String dockerImage = snykConfig.dockerImage
    String imageTag = snykConfig.imageTag
    Boolean scaAnalysis = snykConfig.scaAnalysis
    Boolean iacAnalysis = snykConfig.iacAnalysis
    Boolean sastAnalysis = snykConfig.sastAnalysis
    Boolean containerAnalysis = snykConfig.containerAnalysis
    String environment = snykConfig.environment ? "${snykConfig.environment}" : ""
    String lifecycle = snykConfig.lifecycle ? "${snykConfig.lifecycle}" : ""
    String businessCriticality = snykConfig.businessCriticality ? "${snykConfig.businessCriticality}" : ""

     
        stage('executeScaAnalysis') {
		 when {
			expression { scaAnalysis == true }
		}
		steps {
            catchError(buildResult: 'SUCCESS')  {
               	withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
               	sh """
                   	set +e                        
                   	snyk auth ${TOKEN}
                   	snyk monitor --org=${orgId} --project-name=${projectName} --remote-repo-url=${repoUrl} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${businessCriticality}                    
                   	"""
                   	}
               	}
            }
	    }

       stage('executeIacAnalysis') {
	       when {
			expression { iacAnalysis == true }
		}
            steps {
                catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                    sh """
                        set +e                        
                        snyk auth ${TOKEN}
                        snyk iac test --report --org=${orgId} --remote-repo-url=${repoUrl} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${businessCriticality}
                        """
                        }
                    }
                }            
			}
        stage('executeSastAnalysis') {
		when {
			expression { sastAnalysis == true }
		}
            steps {
                catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                    sh """
                        set +e
                        snyk auth ${TOKEN}
                        snyk code test --severity-threshold=${severity}
                        """
                        }
                    }
                }            
	        }
        stage('executeContainerAnalysis'){
		when {
			expression { containerAnalysis == true }
		}
            steps {
                catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                            sh """
                                set +e
                                snyk auth ${TOKEN}
                                snyk container monitor ${dockerImage}:${imageTag} --org=${orgId} --project-name=${projectName} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${businessCriticality}
                            	"""
                        }
                    }
                }
            }        
        }
