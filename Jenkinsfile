// bastion-app — CI qualité (ruff + pytest + SonarQube)
//
// Jenkins tourne en conteneur avec docker.sock : les chemins du workspace sont
// dans le volume jenkins_data, PAS sur le FS hôte. Il faut donc
// `--volumes-from <conteneur jenkins>` (pas `-v $PWD:/ws`).
//
// Prérequis compose Jenkins :
//   - container_name: jenkins  (ou JENKINS_CONTAINER_NAME)
//   - /var/run/docker.sock + /usr/bin/docker
//
// Prérequis Jenkins UI :
//   - Plugin SonarQube Scanner + serveur nommé SonarQube + token
//   - Webhook Sonar → /sonarqube-webhook/

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
    // Doit matcher container_name du compose Jenkins
    JENKINS_CONTAINER_NAME = "${env.JENKINS_CONTAINER_NAME ?: 'jenkins'}"
  }

  stages {
    stage('Prereqs') {
      steps {
        sh '''
          set -eux
          command -v docker
          docker version
          docker inspect "${JENKINS_CONTAINER_NAME}" >/dev/null
          test -f "${WORKSPACE}/pyproject.toml"
          test -f "${WORKSPACE}/Jenkinsfile"
        '''
      }
    }

    stage('Lint + Test') {
      steps {
        sh '''
          set -eux
          docker run --rm \
            --volumes-from "${JENKINS_CONTAINER_NAME}" \
            -u root:root \
            -w "${WORKSPACE}" \
            -e PIP_DISABLE_PIP_VERSION_CHECK \
            -e PYTHONDONTWRITEBYTECODE \
            "${PYTHON_IMAGE}" \
            bash -lc '
              set -eux
              test -f pyproject.toml
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
            BRANCH="${CHANGE_BRANCH:-${BRANCH_NAME:-main}}"
            docker run --rm \
              --volumes-from "${JENKINS_CONTAINER_NAME}" \
              --entrypoint sonar-scanner \
              -e SONAR_HOST_URL \
              -e SONAR_TOKEN="${SONAR_AUTH_TOKEN}" \
              -w "${WORKSPACE}" \
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
