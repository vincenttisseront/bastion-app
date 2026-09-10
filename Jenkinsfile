// bastion-app — CI qualité (ruff + pytest + SonarQube)
//
// Interconnexion attendue (derrière Bastion) :
//   Jenkins UI     : https://jenkins.example.com
//   SonarQube UI   : https://sonarqube.example.com
//   Scanner → SQ   : https://sonarqube.example.com/api/*  (bypass SSO Bastion + token SQ)
//   SQ → Jenkins   : https://jenkins.example.com/sonarqube-webhook/  (bypass SSO Bastion)
//
// Prérequis Jenkins :
//   1. Plugins : Pipeline, Docker Pipeline, JUnit, SonarQube Scanner
//   2. Manage Jenkins → System → SonarQube servers
//        - Name : SonarQube  (ou override SONAR_SERVER_NAME)
//        - Server URL : https://sonarqube.example.com
//        - Server authentication token (Global Analysis Token SonarQube)
//   3. Sur SonarQube : webhook → https://jenkins.example.com/sonarqube-webhook/
//      (requis pour waitForQualityGate)
//   4. Agent capable de lancer des conteneurs Docker
//   5. Bastion : apps jenkins + sonarqube en subdomain_proxy + Apply infra
//      (chemins /sonarqube-webhook/ et /api/ sans auth_request)
//
// Job : Multibranch Pipeline (Jenkinsfile à la racine) ou Pipeline from SCM.
// Variables optionnelles (job / folder) :
//   SONAR_SERVER_NAME  — défaut SonarQube
//   SONAR_PROJECT_KEY  — défaut bastion-app

pipeline {
  agent none

  options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '30'))
    timeout(time: 45, unit: 'MINUTES')
  }

  environment {
    PIP_DISABLE_PIP_VERSION_CHECK = '1'
    PYTHONDONTWRITEBYTECODE = '1'
    SONAR_SERVER_NAME = "${env.SONAR_SERVER_NAME ?: 'SonarQube'}"
    SONAR_PROJECT_KEY = "${env.SONAR_PROJECT_KEY ?: 'bastion-app'}"
  }

  stages {
    stage('Quality') {
      agent {
        docker {
          image 'python:3.12-bookworm'
          args '-u root:root'
        }
      }
      stages {
        stage('Deps') {
          steps {
            sh '''
              set -eux
              python -m venv .venv
              . .venv/bin/activate
              pip install -U pip
              pip install -e ".[dev]"
            '''
          }
        }

        stage('Lint') {
          steps {
            sh '''
              set -eux
              . .venv/bin/activate
              ruff check app/ tests/
            '''
          }
        }

        stage('Test + coverage') {
          steps {
            sh '''
              set -eux
              . .venv/bin/activate
              mkdir -p reports
              pytest tests/ \
                --ignore=tests/e2e \
                --cov=app \
                --cov-report=xml:coverage.xml \
                --cov-report=term-missing \
                --junitxml=reports/junit.xml \
                -q
            '''
          }
          post {
            always {
              junit allowEmptyResults: true, testResults: 'reports/junit.xml'
              stash name: 'coverage', includes: 'coverage.xml', allowEmpty: true
            }
          }
        }
      }
      post {
        always {
          archiveArtifacts artifacts: 'coverage.xml,reports/junit.xml', allowEmptyArchive: true
        }
      }
    }

    stage('SonarQube') {
      agent {
        docker {
          image 'sonarsource/sonar-scanner-cli:11'
          args '--entrypoint='
        }
      }
      steps {
        checkout scm
        unstash 'coverage'
        withSonarQubeEnv("${SONAR_SERVER_NAME}") {
          sh '''
            set -eux
            BRANCH="${CHANGE_BRANCH:-${BRANCH_NAME:-main}}"
            sonar-scanner \
              -Dsonar.projectKey="${SONAR_PROJECT_KEY}" \
              -Dsonar.branch.name="${BRANCH}"
          '''
        }
      }
    }

    stage('Quality Gate') {
      agent any
      steps {
        timeout(time: 10, unit: 'MINUTES') {
          waitForQualityGate abortPipeline: true
        }
      }
    }
  }
}
