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
    // Full suite (~1500 tests + cov) regularly exceeds 45m on the agent,
    // especially after a Jenkins restart mid-stage. Soft-gated pytest still
    // needs wall-clock room to finish and emit coverage.xml for Sonar.
    timeout(time: 90, unit: 'MINUTES')
  }

  environment {
    PIP_DISABLE_PIP_VERSION_CHECK = '1'
    PYTHONDONTWRITEBYTECODE = '1'
    // Keep durable-task log alive: Python + tee must flush during long pytest.
    PYTHONUNBUFFERED = '1'
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
        // Soft gate: ruff/pytest non-zero, durable-task kill (-1), or missing
        // coverage must not skip SonarQube / Quality Gate.
        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
          sh '''
            set -eux
            docker run --rm \
              --volumes-from "${JENKINS_CONTAINER_NAME}" \
              -u root:root \
              -w "${WORKSPACE}" \
              -e PIP_DISABLE_PIP_VERSION_CHECK \
              -e PYTHONDONTWRITEBYTECODE \
              -e PYTHONUNBUFFERED \
              "${PYTHON_IMAGE}" \
              bash -lc '
                set -eux
                test -f pyproject.toml
                # Reuse workspace venv across builds (volume-backed) to save minutes.
                if [ ! -x .venv/bin/python ]; then
                  python -m venv .venv
                fi
                . .venv/bin/activate
                pip install -U pip
                pip install -e ".[dev]"
                mkdir -p reports

                # Touch Jenkins durable-task log every 60s (JENKINS-48300).
                (
                  while true; do
                    echo "[ci-heartbeat] $(date -u +%Y-%m-%dT%H:%M:%SZ)"
                    sleep 60
                  done
                ) &
                HEARTBEAT_PID=$!
                trap "kill ${HEARTBEAT_PID} 2>/dev/null || true" EXIT

                # Soft gate: large historical ruff debt must not block coverage/Sonar.
                # Failures stay visible in the console and reports/ruff.txt.
                set +e
                ruff check app/ tests/ 2>&1 | tee reports/ruff.txt
                set -e

                # Soft gate: historical pytest failures / flaky ERROR fixtures must
                # not block Sonar. Exit code is recorded; junit + coverage still archive.
                # -o console_output_style=count forces periodic progress lines.
                set +e
                pytest tests/ \
                  --ignore=tests/e2e \
                  --cov=app \
                  --cov-report=xml:coverage.xml \
                  --cov-report=term \
                  --junitxml=reports/junit.xml \
                  -o console_output_style=count \
                  -q 2>&1 | tee reports/pytest.txt
                PYTEST_RC=${PIPESTATUS[0]}
                set -e
                echo "pytest_exit=${PYTEST_RC}" | tee reports/pytest.exit
                if [ ! -f coverage.xml ]; then
                  echo "coverage.xml missing (pytest interrupted or soft-failed early)" \
                    | tee reports/coverage.missing
                fi
              '
          '''
        }
      }
      post {
        always {
          junit allowEmptyResults: true, testResults: 'reports/junit.xml'
          archiveArtifacts artifacts: 'coverage.xml,reports/junit.xml,reports/ruff.txt,reports/pytest.txt,reports/pytest.exit,reports/coverage.missing', allowEmptyArchive: true
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
