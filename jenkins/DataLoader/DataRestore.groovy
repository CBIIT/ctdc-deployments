
@Library('datacommons-jenkins-shared-library@v1.1') _

pipeline {
  agent {
    node {
      label 'ctdc-deploy-agent'
    }
  }

	parameters {
      extendedChoice( 
        name: 'Environment', 
        defaultValue: 'dev', 
        description: 'Choose the environment to build', 
        type: 'PT_SINGLE_SELECT',
        value: 'dev,qa,stage,prod' )
      string(defaultValue: "", 
        description: 'Name of the dump file to use', 
        name: 'DumpFileName')
    
    }

  tools {
  	maven 'Default' 
    jdk 'Default' 
  }
 environment {
    DUMP_FILE = "${params.DumpFileName}"
	TIER      = "${params.Environment}"
    SLACK_SECRET  = "ctdc_slack_url"
    PROGRAM       = "crdc"
    PROJECT       = "ctdc"
    S3_BUCKET     = "crdc-dev-ctdc-neo4j-data-dump"
 }
  stages{

  	stage('create inventory'){
 		steps {
 		  wrap([$class: 'AnsiColorBuildWrapper', colorMapName: "xterm"]) {
			    ansiblePlaybook( 
                playbook: '${WORKSPACE}/ansible/hostfile.yml',
                inventory: '${WORKSPACE}/ansible/hosts',
                extraVars: [
                    tier: "${params.Environment}",
					project_name: "${PROJECT}",
                    workspace: "$WORKSPACE"
				],
                colorized: true)
		  }
 		}
    
  }
  stage("download dump"){
    steps{
      wrap([$class: 'AnsiColorBuildWrapper', colorMapName: "xterm"]) {
			    ansiblePlaybook( 
                playbook: '${WORKSPACE}/ansible/download-dump.yml',
                inventory: '${WORKSPACE}/ansible/hosts',
                colorized: true)
		  }
    }
  }
	stage('restore data dump'){
		steps{			
			ansiblePlaybook( 
                playbook: '${WORKSPACE}/ansible/dump-restore.yml',
                inventory: '${WORKSPACE}/inventory/hosts',
                colorized: true)

		}
	}
	
  }
  post {
    always {
       notify(
            secretPath: "notification/slack",
            secretName: "${env.SLACK_SECRET}"
        ) 
      }
    cleanup {
      cleanWs()
      }
  }
}