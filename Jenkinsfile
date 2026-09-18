// bastion-app — CI qualité (BetterLeaks + ruff + pytest + SonarQube) + DAST TIWAP (OWASP ZAP)
//
// Jenkins tourne en conteneur avec docker.sock : les chemins du workspace sont
// dans le volume jenkins_data, PAS sur le FS hôte. Il faut donc
// `--volumes-from <conteneur jenkins>` (pas `-v $PWD:/ws`).
//
// Ce couplage impose d'exécuter le job sur le contrôleur (même Docker host
// que le conteneur `jenkins`). Les agents inbound distants n'ont ni ce
// conteneur ni le volume workspace — ne pas utiliser `agent any`.
// Le stage ZAP reste donc sur `built-in` (Docker déjà disponible) ; un label
// `linux && docker` sur un agent inbound casserait le montage workspace.
//
// Prérequis compose Jenkins :
//   - container_name: jenkins  (ou JENKINS_CONTAINER_NAME)
//   - /var/run/docker.sock + /usr/bin/docker
//
// Prérequis Jenkins UI :
//   - Plugin SonarQube Scanner + serveur nommé SonarQube + token
//   - Webhook Sonar → /sonarqube-webhook/
//   - nœud built-in (affichage « contrôleur ») avec label `built-in`
//   - Job/global env TIWAP_URL = URL staging de l'app vulnérable de test (DAST)
//   - Credential Jenkins (Username/Password) id `tiwap-dast` : compte local TIWAP
//     (ex. admin / admin) — pas breakglass / Keycloak
//   - Rapport HTML : artefact Jenkins reports/tiwap/*zap-report* (pas de plugin HTML Publisher)
//   - BetterLeaks (ghcr.io/betterleaks/betterleaks) : secrets scan, rapport JSON archivé

pipeline {
  agent { label 'built-in' }

  options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '30'))
    // Full suite (~1500 tests + cov) regularly exceeds 45m on the agent,
    // especially after a Jenkins restart mid-stage. Soft-gated pytest still
    // needs wall-clock room to finish and emit coverage.xml for Sonar.
    // zap-full-scan.py (spider + active) ajoute souvent 30–90 min.
    timeout(time: 180, unit: 'MINUTES')
  }

  environment {
    PIP_DISABLE_PIP_VERSION_CHECK = '1'
    PYTHONDONTWRITEBYTECODE = '1'
    // Keep durable-task log alive: Python + tee must flush during long pytest.
    PYTHONUNBUFFERED = '1'
    SONAR_SERVER_NAME = "${env.SONAR_SERVER_NAME ?: 'SonarQube'}"
    SONAR_PROJECT_KEY = "${env.SONAR_PROJECT_KEY ?: 'bastion-app'}"
    PYTHON_IMAGE = 'python:3.12-bookworm'
    SONAR_SCANNER_IMAGE = 'sonarsource/sonar-scanner-cli:12'
    // Doit matcher container_name du compose Jenkins
    JENKINS_CONTAINER_NAME = "${env.JENKINS_CONTAINER_NAME ?: 'jenkins'}"
    // Réseau Docker partagé jenkins ↔ sonarqube (inspect: NetworkSettings.Networks).
    // Sans ça, `docker run` sonar-scanner est sur bridge et ne résout pas
    // http://sonarqube:9000 (ou passe par une URL publique/proxy qui casse le protobuf).
    SONAR_DOCKER_NETWORK = "${env.SONAR_DOCKER_NETWORK ?: 'external'}"
    // URL interne (hostname Docker). Préférer ça dans Jenkins → SonarQube servers.
    SONAR_INTERNAL_URL = "${env.SONAR_INTERNAL_URL ?: 'http://sonarqube:9000'}"
    // Cible DAST (app de test volontairement vulnérable). Override dans le job Jenkins.
    TIWAP_URL = "${env.TIWAP_URL ?: 'https://tiwap.example.com'}"
    // Username/Password credential (compte local Flask TIWAP, pas SSO).
    TIWAP_CREDENTIALS_ID = "${env.TIWAP_CREDENTIALS_ID ?: 'tiwap-dast'}"
    ZAP_IMAGE = "${env.ZAP_IMAGE ?: 'ghcr.io/zaproxy/zaproxy:stable'}"
    BETTERLEAKS_IMAGE = "${env.BETTERLEAKS_IMAGE ?: 'ghcr.io/betterleaks/betterleaks:latest'}"
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

    // Secrets scan (BetterLeaks, successeur Gitleaks). Soft gate phase 1 : findings → UNSTABLE,
    // rapport JSON archivé ; retirer catchError pour bloquer le build sur fuite.
    stage('BetterLeaks') {
      steps {
        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
          timeout(time: 20, unit: 'MINUTES') {
            sh '''
              set -eux
              mkdir -p "${WORKSPACE}/reports/betterleaks"
              chmod -R a+rwX "${WORKSPACE}/reports/betterleaks"
              test -f "${WORKSPACE}/.betterleaks.toml"

              # Arbre courant (toujours) + historique git disponible (clone Jenkins).
              # Note: image stable utilise --git-workers (pas --source-workers de la doc main).
              set +e
              docker run --rm \
                --volumes-from "${JENKINS_CONTAINER_NAME}" \
                -u root:root \
                -w "${WORKSPACE}" \
                "${BETTERLEAKS_IMAGE}" \
                dir . \
                  --config .betterleaks.toml \
                  --redact \
                  --report-path reports/betterleaks/findings-dir.json \
                  --report-format json \
                  -v
              DIR_RC=$?
              docker run --rm \
                --volumes-from "${JENKINS_CONTAINER_NAME}" \
                -u root:root \
                -w "${WORKSPACE}" \
                "${BETTERLEAKS_IMAGE}" \
                git . \
                  --config .betterleaks.toml \
                  --git-workers 8 \
                  --redact \
                  --report-path reports/betterleaks/findings-git.json \
                  --report-format json \
                  --platform github \
                  -v
              GIT_RC=$?
              set -e

              echo "betterleaks_dir_exit=${DIR_RC}" | tee "${WORKSPACE}/reports/betterleaks/exit.txt"
              echo "betterleaks_git_exit=${GIT_RC}" | tee -a "${WORKSPACE}/reports/betterleaks/exit.txt"
              ls -lah "${WORKSPACE}/reports/betterleaks" || true

              # Non-zero si fuites (ou erreur outil) sur dir ou git.
              if [ "${DIR_RC}" -ne 0 ] || [ "${GIT_RC}" -ne 0 ]; then
                exit 1
              fi
            '''
          }
        }
      }
      post {
        always {
          archiveArtifacts(
            artifacts: 'reports/betterleaks/**',
            allowEmptyArchive: true,
            fingerprint: true
          )
        }
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
              -e PORTAL_ENVIRONMENT=test \
              -e DATABASE_URL=sqlite:////tmp/bastion-ci-portal.db \
              "${PYTHON_IMAGE}" \
              bash -lc '
                set -eux
                test -f pyproject.toml
                # Safety net if any import still opens the module-level engine
                # before conftest patches lifespan onto in-memory sqlite.
                mkdir -p /tmp
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
        // Soft gate: scanner/server protobuf or proxy issues must not fail the
        // whole job after pytest already produced coverage for archival.
        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
          withSonarQubeEnv("${SONAR_SERVER_NAME}") {
            // Community Build rejects sonar.branch.name (Developer+ only).
            // Lint+Test runs python as root → root-owned coverage; scanner must
            // run as root and reset .scannerwork.
            sh '''
              set -eux
              docker run --rm \
                --volumes-from "${JENKINS_CONTAINER_NAME}" \
                -u root:root \
                -w "${WORKSPACE}" \
                "${PYTHON_IMAGE}" \
                bash -lc "rm -rf .scannerwork && mkdir -p .scannerwork && chmod -R a+rwX .scannerwork coverage.xml reports 2>/dev/null || true"
              # Join the same Docker network as sonarqube; force internal URL so
              # /batch/project.protobuf is not mangled by a reverse-proxy/WAF.
              docker run --rm \
                --volumes-from "${JENKINS_CONTAINER_NAME}" \
                --network "${SONAR_DOCKER_NETWORK}" \
                -u root:root \
                --entrypoint sonar-scanner \
                -e SONAR_HOST_URL="${SONAR_INTERNAL_URL}" \
                -e SONAR_TOKEN="${SONAR_AUTH_TOKEN}" \
                -w "${WORKSPACE}" \
                "${SONAR_SCANNER_IMAGE}" \
                -Dsonar.projectKey="${SONAR_PROJECT_KEY}"
            '''
          }
        }
      }
    }

    stage('Quality Gate') {
      steps {
        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
          timeout(time: 10, unit: 'MINUTES') {
            waitForQualityGate abortPipeline: true
          }
        }
      }
    }

    // DAST contre l'app de test exposée (indépendant de l'analyse Sonar du code).
    // Auth : login form TIWAP (credential tiwap-dast) → cookie session injecté dans ZAP.
    // Soft gate : -I + exit 0 (pas encore de règles FAIL SQLi/XSS/…).
    stage('TIWAP DAST - OWASP ZAP') {
      steps {
        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
          timeout(time: 90, unit: 'MINUTES') {
            withCredentials([usernamePassword(
              credentialsId: "${TIWAP_CREDENTIALS_ID}",
              usernameVariable: 'TIWAP_USER',
              passwordVariable: 'TIWAP_PASS'
            )]) {
              sh '''
                set -eux
                mkdir -p "${WORKSPACE}/reports/tiwap"
                chmod -R a+rwX "${WORKSPACE}/reports/tiwap"
                COOKIE_JAR="${WORKSPACE}/reports/tiwap/cookies.txt"
                SESSION_PROP="${WORKSPACE}/reports/tiwap/session.prop"
                rm -f "${COOKIE_JAR}" "${SESSION_PROP}"

                echo "Préflight HTTP vers ${TIWAP_URL}"
                set +e
                curl -k -sS -o /dev/null -w "tiwap_http_code=%{http_code}\\n" --connect-timeout 10 --max-time 30 -I "${TIWAP_URL}/" \
                  | tee "${WORKSPACE}/reports/tiwap/preflight.txt"
                set -e

                echo "Auth TIWAP (form /login) pour user=${TIWAP_USER}"
                # Ne pas suivre Location http://… : on ne garde que Set-Cookie.
                curl -k -sS -c "${COOKIE_JAR}" \
                  -X POST "${TIWAP_URL}/login" \
                  -H 'Content-Type: application/x-www-form-urlencoded' \
                  --data-urlencode "username=${TIWAP_USER}" \
                  --data-urlencode "password=${TIWAP_PASS}" \
                  -D "${WORKSPACE}/reports/tiwap/login.headers" \
                  -o "${WORKSPACE}/reports/tiwap/login.body" \
                  --max-time 30

                SESSION="$(awk '$6 == "session" { print $7 }' "${COOKIE_JAR}" | tail -1)"
                if [ -z "${SESSION}" ]; then
                  echo "AUTH_FAIL: pas de cookie session après /login" | tee "${WORKSPACE}/reports/tiwap/auth.probe.txt"
                  exit 1
                fi

                DASH_CODE="$(curl -k -sS -o "${WORKSPACE}/reports/tiwap/dashboard.probe.html" -w "%{http_code}" \
                  -b "session=${SESSION}" --max-time 30 "${TIWAP_URL}/dashboard")"
                echo "dashboard_http_code=${DASH_CODE}" | tee "${WORKSPACE}/reports/tiwap/auth.probe.txt"
                if [ "${DASH_CODE}" != "200" ]; then
                  echo "AUTH_FAIL: /dashboard attendu 200, obtenu ${DASH_CODE}"
                  exit 1
                fi

                # Config ZAP : injecter Cookie sur toutes les requêtes (hors dépôt public).
                printf '%s\n' \
                  'replacer.full_list(0).description=tiwap_session' \
                  'replacer.full_list(0).enabled=true' \
                  'replacer.full_list(0).matchtype=REQ_HEADER' \
                  'replacer.full_list(0).matchstr=Cookie' \
                  "replacer.full_list(0).replacement=session=${SESSION}" \
                  > "${SESSION_PROP}"

                echo "Scan ZAP (full, authentifié) de ${TIWAP_URL}"
                set +e
                docker run --rm -t \
                  --volumes-from "${JENKINS_CONTAINER_NAME}" \
                  --network host \
                  --entrypoint '' \
                  -u root:root \
                  -e HOME=/home/zap \
                  "${ZAP_IMAGE}" \
                  bash -lc "
                    set -eux
                    rm -rf /zap/wrk
                    ln -s '${WORKSPACE}/reports/tiwap' /zap/wrk
                    /zap/zap-full-scan.py \
                      -t '${TIWAP_URL}' \
                      -j \
                      -z '-configfile /zap/wrk/session.prop' \
                      -r tiwap-zap-report.html \
                      -J tiwap-zap-report.json \
                      -x tiwap-zap-report.xml \
                      -I
                  "
                ZAP_EXIT_CODE=$?
                set -e

                echo "Code retour ZAP : ${ZAP_EXIT_CODE}" | tee "${WORKSPACE}/reports/tiwap/zap.exit"
                # Ne pas archiver le cookie / session.prop (secret de session).
                rm -f "${COOKIE_JAR}" "${SESSION_PROP}" "${WORKSPACE}/reports/tiwap/login.body"
                ls -lah "${WORKSPACE}/reports/tiwap" || true

                # Soft gate : rapports conservés, build non bloqué par les findings.
                exit 0
              '''
            }
          }
        }
      }
      post {
        always {
          sh '''
            rm -f "${WORKSPACE}/reports/tiwap/cookies.txt" \
                  "${WORKSPACE}/reports/tiwap/session.prop" \
                  "${WORKSPACE}/reports/tiwap/login.body" \
                  2>/dev/null || true
          '''
          archiveArtifacts(
            artifacts: 'reports/tiwap/**',
            allowEmptyArchive: true,
            fingerprint: true
          )
        }
      }
    }
  }
}
