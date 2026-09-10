// bastion-app — CI qualité (ruff + pytest + SonarQube)
//
// Compatible Jenkins "built-in" sans plugin Docker Pipeline et sans docker CLI.
// Prérequis agent :
//   - python3 + venv (python3-venv)
//   - curl, unzip (pour le sonar-scanner)
//   - plugin SonarQube Scanner (withSonarQubeEnv / waitForQualityGate)
//
// Sur une image jenkins/jenkins minimale :
//   apt-get update && apt-get install -y python3 python3-venv python3-pip curl unzip
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
    // Linux x64 scanner — override if needed
    SONAR_SCANNER_VERSION = "${env.SONAR_SCANNER_VERSION ?: '6.2.1.4610'}"
  }

  stages {
    stage('Prereqs') {
      steps {
        sh '''
          set -eux
          if ! command -v python3 >/dev/null 2>&1; then
            echo "python3 manquant sur l'agent Jenkins." >&2
            echo "Installer: python3 python3-venv python3-pip curl unzip" >&2
            exit 1
          fi
          python3 --version
          command -v curl
          command -v unzip
        '''
      }
    }

    stage('Lint + Test') {
      steps {
        sh '''
          set -eux
          python3 -m venv .venv
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
            SCANNER_HOME="$WORKSPACE/.sonar-scanner"
            if [ ! -x "$SCANNER_HOME/bin/sonar-scanner" ]; then
              rm -rf "$SCANNER_HOME"
              mkdir -p "$SCANNER_HOME"
              curl -fsSL \
                "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip" \
                -o /tmp/sonar-scanner.zip
              unzip -q /tmp/sonar-scanner.zip -d /tmp
              mv /tmp/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64/* "$SCANNER_HOME"/
              rm -rf /tmp/sonar-scanner.zip /tmp/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64
            fi
            BRANCH="${CHANGE_BRANCH:-${BRANCH_NAME:-main}}"
            export SONAR_TOKEN="${SONAR_AUTH_TOKEN}"
            "$SCANNER_HOME/bin/sonar-scanner" \
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
