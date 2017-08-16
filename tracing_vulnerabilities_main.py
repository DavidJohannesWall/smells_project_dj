import subprocess
import os

# Projets à traiter
projects = ['expressjs/express','bower/bower','less/less.js','request/request','gruntjs/grunt','jquery/jquery','vuejs/vue','ramda/ramda','Leaflet/Leaflet','hexojs/hexo','chartjs/Chart.js','webpack/webpack','moment/moment','webtorrent/webtorrent','riot/riot']

# Pour chacun des projets
for project in projects:

    # On se place dans le répertoire du projet
    print('Le projet',project,'est traité !')
    os.chdir(project.split('/')[0])

    # On trace les vulnérabilités du projet traité
    os.system('python3 tracing_vulnerabilities.py > vulnerabilities.txt')

    # On collecte les informations sur les vulnérabilités (commit dans lequel elles apparaissent pour la première fois) ainsi que les emplacements (lignes) potentiels de vulnérabilité
    os.system("python3 modify_vulnerabilities.py > emplacements_vulnerabilites.txt")

    # On collecte les emplacements potentiels de vulnérabilité au sens large (en considérant les dépendances)
    os.system("python3 modify_vulnerabilities_large.py > emplacements_vulnerabilites_large.txt")

    # On génère les données à analyser (liens entre vulnérabilités et code smells)
    subprocess.run(['python3','smelly_vulnerable.py'])

    # On génère les courbes de survies pour chaque type de variable et type d'analyse, à l'aide d'un modèle Cox
    subprocess.run(['Rscript','analyze3.r'])

    # On revient dans le répertoire parent
    os.chdir('..')
    print()