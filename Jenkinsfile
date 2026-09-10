// bastion-app — CI qualité (ruff + pytest + SonarQube)
//
// Compatible Jenkins sans plugin "Docker Pipeline" (agent types: any | label | none).
// Prérequis agent : Docker CLI (docker run) + plugin SonarQube Scanner (withSonarQubeEnv).
//
// Prérequis Jenkins :
//   1. Plugins : Pipeline, JUnit, SonarQube Scanner
//   2. Manage Jenkins → System → SonarQube servers
//        - Name : SonarQube
//        - Server URL + Server authentication token (Secret text)
//   3. SonarQube webhook → https://jenkins…/sonarqube-webhook/
//   4. Agent Linux avec `docker` (groupe jenkins) pour pull python / sonar-scanner-cli
//
// Variables optionnelles :
//   SONAR_SERVER_NAME  — défaut SonarQube
//   SONAR_PROJECT_KEY  — défaut bastion-app

pipeline {
  agent any

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
    PYTHON_IMAGE = 'python:3.12-bookworm'
    SONAR_SCANNER_IMAGE = 'sonarsource/sonar-scanner-cli:11'
  }

  stages {
    stage('Lint + Test') {
      steps {
        sh '''
          set -eux
          command -v docker >/dev/null
          docker run --rm \
            -u root:root \
            -v "$PWD":/ws \
            -w /ws \
            -e PIP_DISABLE_PIP_VERSION_CHECK \
            -e PYTHONDONTWRITEBYTECODE \
            "${PYTHON_IMAGE}" \
            bash -lc '
              set -eux
              python -m venv .venv
              . .venv/bin/activate
              pip install -U pip
              pip install -e ".[dev]"
              ruff check app/ tests/
              mkdir -p reports
              pytest tests/ \
                --ignore=tests/e2e \
                --cov=app \
                --cov-report=xml:coverage.xml \
                --cov-report=term-missing \
                --junitxml=reports/junit.xml \
                -q
            '
        '''
      }
      post {
        always {
          junit allowEmptyResults: true, testResults: 'reports/junit.xml'
          archiveArtifacts artifacts: 'coverage.xml,reports/junit.xml', allowEmptyArchive: true
        }
      }
    }

    stage('SonarQube') {
      steps {
        withSonarQubeEnv("${SONAR_SERVER_NAME}") {
          sh '''
            set -eux
            command -v docker >/dev/null
            BRANCH="${CHANGE_BRANCH:-${BRANCH_NAME:-main}}"
            # withSonarQubeEnv fournit SONAR_HOST_URL + SONAR_AUTH_TOKEN
            docker run --rm \
              --entrypoint sonar-scanner \
              -e SONAR_HOST_URL \
              -e SONAR_TOKEN="${SONAR_AUTH_TOKEN}" \
              -v "$PWD":/usr/src \
              -w /usr/src \
              "${SONAR_SCANNER_IMAGE}" \
              -Dsonar.projectKey="${SONAR_PROJECT_KEY}" \
              -Dsonar.branch.name="${BRANCH}"
          '''
        }
      }
    }

    stage('Quality Gate') {
      steps {
        timeout(time: 10, unit: 'MINUTES') {
          waitForQualityGate abortPipeline: true
        }
      }
    }
  }
}
