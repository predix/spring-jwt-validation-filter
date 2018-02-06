#!groovy

// Define DevCloud Artifactory for publishing non-docker image artifacts
def devcloudArtServer = Artifactory.server('devcloud')
def predixExternalArtServer = Artifactory.server('predix-external')

// Change Snapshot to your own DevCloud Artifactory repo name
def Snapshot = 'PROPEL'

pipeline {
    agent none
    options {
        buildDiscarder(logRotator(artifactDaysToKeepStr: '1', artifactNumToKeepStr: '1', daysToKeepStr: '5', numToKeepStr: '10'))
    }
    stages {
        stage ('Build and Test') {
            agent {
                docker {
                    image 'maven:3.5'
                    label 'dind'
                    args '-v /root/.m2:/root/.m2'
                }
            }
            steps {
                echo env.BRANCH_NAME
                sh '''#!/bin/bash -ex
                    unset HTTPS_PROXY
                    unset HTTP_PROXY
                    unset http_proxy
                    unset https_proxy
                    mvn clean install
                '''
                dir('target') {
                    stash includes: '*.jar', name: 'uaa-token-lib-jar'
                }
            }
             post {
                always {
                    junit '**/surefire-reports/junitreports/TEST*.xml'
                }
                success {
                    echo 'Build and Test stage completed'
                }
                failure {
                    echo 'Build and Test stage failed'
                }
            }
        }
        stage('Publish Artifacts') {
            agent {
                label 'dind'
            }
            when {
                expression { env.BRANCH_NAME == 'master' || env.BRANCH_NAME == 'develop' }
            }
            steps {
                dir('spring-filters-config') {
                    git branch: 'master', changelog: false, credentialsId: 'github.build.ge.com', poll: false, url: 'https://github.build.ge.com/predix/spring-filters-config'
                }
                unstash 'uaa-token-lib-jar'
                script {
                    APP_VERSION = sh (returnStdout: true, script: '''
                        grep '<version>' pom.xml -m 1 | sed 's/<version>//' | sed 's/<\\/version>//g'
                        ''').trim()
                    echo "Uploading UAA ${APP_VERSION} build to Artifactory"
                    if (env.BRANCH_NAME == 'master') {
                        echo 'Branch is master push to MAAXA-MVN, PREDIX-EXT, and maven central'
                        def uploadSpec = """{
                            "files": [
                                    {
                                        "pattern": "uaa-token-lib-${APP_VERSION}.jar",
                                        "target": "MAAXA-MVN/com/ge/predix/uaa-token-lib/${APP_VERSION}/"
                                    }
                                ]
                            }"""

                        def buildInfo = devcloudArtServer.upload(uploadSpec)
                        devcloudArtServer.publishBuildInfo(buildInfo)

                        uploadSpec.target = "PREDIX-EXT/com/ge/predix/uaa-token-lib/${APP_VERSION}/"
                        buildInfo = predixExternalArtServer.upload(uploadSpec)
                        predixExternalArtServer.publishBuildInfo(buildInfo)

                        sh (returnStdout: true, script: '''
                            #Deploy/Release to maven central repository
                            mvn clean deploy -P release -s spring-filters-config/mvn_settings_noproxy.xml -D stagingProfileId=14c243d3be5b9e -e
                        ''')
                    }
                    else {
                        echo 'Branch is develop push to MAAXA-MVN-SNAPSHOT'
                        def  uploadSpec = """{
                                "files": [
                                    {
                                        "pattern": "uaa-token-lib-${APP_VERSION}.jar",
                                        "target": "MAAXA-MVN-SNAPSHOT/com/ge/predix/uaa-token-lib/${APP_VERSION}/"
                                    }
                                ]
                            }"""
                        def buildInfo = devcloudArtServer.upload(uploadSpec)
                        devcloudArtServer.publishBuildInfo(buildInfo)
                    }
                }

            }
            post {
                success {
                    echo 'Publish artifacts stage completed'
                }
                failure {
                    echo 'Publish artifacts stage failed'
                }
            }
        }

    }
    post {
        success {
            echo 'Pipeline completed'
        }
        failure {
            echo 'Pipeline failed'
        }
    }
}