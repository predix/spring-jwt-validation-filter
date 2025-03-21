#!groovy

// Define Artifactory for publishing non-docker image artifacts
def digitalGridArtServer = Artifactory.server('Digital-Artifactory')
def ARTIFACTORY_SERVER_URL = digitalGridArtServer.getUrl()
library "security-ci-commons-shared-lib"

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
                    image 'maven:3.9.9-amazoncorretto-21-alpine'
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
                    mvn -B clean install
                '''
                dir('target') {
                    stash includes: '*.jar', name: 'uaa-token-lib-jar'
                }
            }
             post {
                always {
                    junit '**/surefire-reports/junitreports/TEST*.xml'
                    step([$class: 'JacocoPublisher', execPattern: '**/**.exec', maximumBranchCoverage: '90', maximumInstructionCoverage: '90'])
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
                docker {
                    image 'maven:3.9.9-amazoncorretto-21-alpine'
                    label 'dind'
                    args '-v /root/.m2:/root/.m2'
                }
            }
            when {
                beforeAgent true
                expression { env.BRANCH_NAME == 'master' || env.BRANCH_NAME == 'develop' }
            }
            environment {
                DEPLOY_CREDS = credentials('DIGITAL_GRID_ARTIFACTORY_CREDENTIALS')
                MAVEN_CENTRAL_STAGING_PROFILE_ID=credentials('MAVEN_CENTRAL_STAGING_PROFILE_ID')
            }
            steps {
                dir('spring-filters-config') {
                    git branch: 'master', changelog: false, credentialsId: 'github.software.gevernova.com', poll: false, url: 'https://github.software.gevernova.com/pers/spring-filters-config.git'
                }
                unstash 'uaa-token-lib-jar'
                script {
                    APP_VERSION = sh (returnStdout: true, script: '''
                        grep '<version>' pom.xml -m 1 | sed 's/<version>//' | sed 's/<\\/version>//g'
                        ''').trim()
                    echo "Uploading uaa-token-lib ${APP_VERSION} build to Artifactory"
                    if (env.BRANCH_NAME == 'master') {
                        ARTIFACTORY_REPO = 'pgog-fss-iam-uaa-mvn'
                        echo "Branch is master push to ${ARTIFACTORY_REPO}, and maven central"

                        sh """#!/usr/bin/env bash
                            set -ex
                            apk update
                            apk add --no-cache gnupg
                            gpg --version
                            ln -s ${WORKSPACE} /working-dir

                            #Deploy/Release to digital grid repository
                            mvn clean deploy -B -s spring-filters-config/mvn_settings_noproxy.xml \\
                            -DaltDeploymentRepository=artifactory.uaa.releases::default::${ARTIFACTORY_SERVER_URL}/${ARTIFACTORY_REPO} \\
                            -Dartifactory.user=${DEPLOY_CREDS_USR} \\
                            -Dartifactory.password=${DEPLOY_CREDS_PSW} \\
                            -DskipTests -e

                            #Deploy/Release to maven central repository
                            mvn -B clean deploy -B -P release -s spring-filters-config/mvn_settings_noproxy.xml \\
                             -D gpg.homedir=/working-dir/spring-filters-config/gnupg -D stagingProfileId=$MAVEN_CENTRAL_STAGING_PROFILE_ID \\
                             -D skipTests -e
                        """
                    }
                    else {
                        ARTIFACTORY_REPO = 'pgog-fss-iam-uaa-mvn-snapshot'
                        echo "Branch is develop push to ${ARTIFACTORY_REPO}"

                        sh """#!/usr/bin/env bash
                            set -ex
                            apk update
                            apk add --no-cache gnupg
                            gpg --version
                            ln -s ${WORKSPACE} /working-dir
                    
                            mvn clean deploy -B -s spring-filters-config/mvn_settings_noproxy.xml \\
                            -DaltDeploymentRepository=artifactory.uaa.snapshots::default::${ARTIFACTORY_SERVER_URL}/${ARTIFACTORY_REPO} \\
                            -Dartifactory.user=${DEPLOY_CREDS_USR} \\
                            -Dartifactory.password=${DEPLOY_CREDS_PSW} \\
                            -DskipTests -e
                        """
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
