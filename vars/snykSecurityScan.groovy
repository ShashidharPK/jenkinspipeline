/* To connect with the snyk dashboard SNYK_TOKEN should be set up in the Jenkins environment as a secret variable
*  For executing the snyk.groovy there are some mandatory variables that needs to be passed from jenkinsfile
*  Required Variables where the build fails when the values is not passed
*  repoUrl: URL of the repository that needs to be scanned. This is a mandatory field
*  severity: Severity of the vulnerabilities where the scans fail. Default: high
*  orgId: Snyk Organization id. This is a mandatory field
*  projectName: Name of the project as it is displayed in Snyk. This is a mandatory field
*  dockerImage: Image which needs to be scanned. This is a mandatory field
*  imageTag: Tag of the docker image. Default: latest
*  performAppAnalysis: Set to true, SCA and SAST analysis are performed. Default: false
*  iacAnalysis: Set to true, IAC scans are performed. Default: false
*  containerAnalysis: Set to true, Container scans are performed. Default: false
*  environment: Environment tag displayed in snyk. Default: null
*  lifecycle: Lifecycle tag displayed in snyk. Default: null
*  businessCriticality: Business criticality tag displayed in snyk. Default: null
*  appFindings: Decides whether to pass or fail the builds when vulnerabilities are found. Default: SUCCESS
*/
def call(Map snykConfig) {

    String repoUrl = snykConfig.repoUrl ? "${snykConfig.repoUrl}" : ""
    String severity = snykConfig.severity ? "${snykConfig.severity}" : "high"
    String orgId = snykConfig.orgId ? "${snykConfig.orgId}" : ""
    String projectName = snykConfig.projectName ? "${snykConfig.projectName}" : ""
    String dockerImage = snykConfig.dockerImage ? "${snykConfig.dockerImage}" : ""
    String imageTag = snykConfig.imageTag ? "${snykConfig.imageTag}" : "latest"
    String performAppAnalysis = snykConfig.performAppAnalysis ? "${snykConfig.performAppAnalysis}" : "false" //Performs SCA and SAST analysis if performAppAnalysis is set to true
    String iacAnalysis = snykConfig.iacAnalysis ? "${snykConfig.iacAnalysis}" : "false"
    String containerAnalysis = snykConfig.containerAnalysis ? "${snykConfig.containerAnalysis}" : "false"
    //Environment, lifecycle and business criticality are tags provided for each project in Snyk. Null value will be taken by default if the value is not provided
    String environment = snykConfig.environment ? "${snykConfig.environment}" : "" 
    String lifecycle = snykConfig.lifecycle ? "${snykConfig.lifecycle}" : ""
    String businessCriticality = snykConfig.businessCriticality ? "${snykConfig.businessCriticality}" : ""
    String appFindings = snykConfig.appFindings ? "${snykConfig.appFindings}" : "SUCCESS"

     
        stage('executeScaAnalysis') {
		 
		    if ( performAppAnalysis == "true" ) {
                catchError(buildResult: "${appFindings}")  {
                   	withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                   	sh """
			if test -z "$repoUrl" || test -z "$orgId" || test -z "$projectName"
			then
				echo "Variables repoUrl or orgId or projectName is not defined"
				exit 1
			fi
                       	snyk auth ${TOKEN}
                       	snyk monitor --org=${orgId} --project-name=${projectName} --remote-repo-url=${repoUrl} --severity-threshold=${severity} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${businessCriticality}
                       	"""
                       	}
                   	}
                }
	        }
        
        stage('executeSastAnalysis') {
		    if ( performAppAnalysis == "true" ) {
                catchError(buildResult: "${appFindings}")  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                    sh """
                        snyk auth ${TOKEN}
                        snyk code test --severity-threshold=${severity}
                        """
                        }
                    }
                }
	        }

        stage('executeIacAnalysis') {
	      
			if ( iacAnalysis == "true" ) {
                catchError(buildResult: "${appFindings}")  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                    sh """
			if test -z "$repoUrl" || test -z "$orgId"
			then
				echo "Variables repoUrl or orgId or projectName is not defined"
				exit 1
			fi   
                        snyk auth ${TOKEN}
                        snyk iac test --report --org=${orgId} --remote-repo-url=${repoUrl} --severity-threshold=${severity} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${businessCriticality}
                        """
                        }
                    }
                }
			}
        stage('executeContainerAnalysis'){
		    // Checks for application vulnerability from the container images
		    if ( containerAnalysis == "true" && performAppAnalysis == "true" ) {
                catchError(buildResult: "${appFindings}")  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                            sh """
				if test -z "$repoUrl" || test -z "$orgId" || test -z "$projectName" || test -z "$dockerImage"
				then
					echo "Variables repoUrl or orgId or projectName is not defined"
					exit 1
				fi                
                                snyk auth ${TOKEN}                               
                                snyk container monitor ${dockerImage}:${imageTag} --org=${orgId} --severity-threshold=${severity} --project-name=${projectName} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${businessCriticality} --app-vulns
                            	"""
                        }
                    }
                }
            if ( containerAnalysis == "true" && performAppAnalysis == "false" ) {
                catchError(buildResult: "${appFindings}")  {
                    withCredentials([string(credentialsId: 'snyk-token', variable: 'TOKEN')])  {
                            sh """
                                snyk auth ${TOKEN}                               
                                snyk container monitor ${dockerImage}:${imageTag} --org=${orgId} --severity-threshold=${severity} --project-name=${projectName} --project-environment=${environment} --project-lifecycle=${lifecycle} --project-business-criticality=${businessCriticality}
                            	"""
                        }
                    }
                }
            }
        }
