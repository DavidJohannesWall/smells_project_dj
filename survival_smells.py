import subprocess
import os

# Projets à traiter
projects = ['expressjs/express','bower/bower','less/less.js','request/request','gruntjs/grunt','jquery/jquery','vuejs/vue','ramda/ramda','Leaflet/Leaflet','hexojs/hexo','chartjs/Chart.js','webpack/webpack','moment/moment','webtorrent/webtorrent','riot/riot']

# Pour chacun des projets
for project in projects:

    # On se place dans le répertoire du projet
    print('Le projet',project,'est traité !')
    os.chdir(project.split('/')[0])

    # On génère les données de survies pour chacun des types de smell
    subprocess.run(['python3','survival_code_smells.py','0.7'])

    # On génère les courbes de survies pour chaque type de smell, à l'aide d'un modèle Cox
    subprocess.run(['Rscript','analyze.r'])

    # On revient dans le répertoire parent
    os.chdir('..')
    print()