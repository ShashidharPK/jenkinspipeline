def call(Map snykConfig) {

    String repoUrl = snykConfig.repoUrl
    String severity = snykConfig.severity
    String orgId = snykConfig.orgId
    String projectName = snykConfig.projectName    
    String dockerImage = snykConfig.dockerImage
    String imageTag = snykConfig.imageTag
    Boolean performAppAnalysis = snykConfig.performAppAnalysis //Performs SCA and SAST analysis if performAppAnalysis is set to true
    Boolean iacAnalysis = snykConfig.iacAnalysis    
    Boolean containerAnalysis = snykConfig.containerAnalysis
    //Environment, lifecycle and business criticality are tags provided for each project in Snyk. Null value will be taken by default if the value is not provided
    String environment = snykConfig.environment ? "${snykConfig.environment}" : "" 
    String lifecycle = snykConfig.lifecycle ? "${snykConfig.lifecycle}" : ""
    String businessCriticality = snykConfig.businessCriticality ? "${snykConfig.businessCriticality}" : ""

     
        stage('executeScaAnalysis') {
		 
		    if (performAppAnalysis == true) {
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
        
        stage('executeSastAnalysis') {
		    if ( performAppAnalysis == true ) {
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

        stage('executeIacAnalysis') {
	      
			if ( iacAnalysis == true ) {
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
        stage('executeContainerAnalysis'){
		    // Checks for application vulnerability from the container images
		    if ( containerAnalysis == true && performAppAnalysis == true ) {
                catchError(buildResult: 'SUCCESS')  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                            sh """
                                set +e
                                snyk auth ${TOKEN}                               
                                snyk container monitor ${dockerImage}:${imageTag} --org=${orgId} --project-name=${projectName} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${businessCriticality} --app-vulns
                            	"""
                        }
                    }
                }
            if ( containerAnalysis == true && performAppAnalysis == false ) {
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
