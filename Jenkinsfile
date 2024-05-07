pipeline {
  agent {
    node {
      label 'agent01'
    }

  }
  stages {
    stage('Source') {
      steps {
        git(url: 'https://github.com/3maestro/study.git', branch: 'master', changelog: true, credentialsId: '3maestro')
      }
    }

    stage('Deploy') {
      steps {
        sh 'echo "Deploy Success"'
      }
    }

  }
}