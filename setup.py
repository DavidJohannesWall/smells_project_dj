import subprocess
import os

# Projets à traiter
projects = ['expressjs/express','bower/bower','less/less.js','request/request','gruntjs/grunt','jquery/jquery','vuejs/vue','ramda/ramda','Leaflet/Leaflet','hexojs/hexo','chartjs/Chart.js','webpack/webpack','moment/moment','webtorrent/webtorrent','riot/riot']

# Pour chacun des projets
for project in projects:

    # On se place dans le répertoire du projet
    print('Le projet',project,'est traité !')
    os.chdir(project.split('/')[0])

    # On copie le projet depuis github
    subprocess.run(['rm','-rf','uut'])
    subprocess.run(['git','clone','https://github.com/'+project+'.git','uut'])

    # On récupère tous les commits du projet
    subprocess.run(['rm','-rf','commits-data'])
    subprocess.run(['mkdir','commits-data'])
    os.system('node commits.js > /dev/null')

    # On clean les informations sur les commits du projet
    subprocess.run(['rm','-rf','commits-clean'])
    subprocess.run(['mkdir','commits-clean'])
    subprocess.run(['node','clean.js'])

    # On réunit les informations concernant les smells qui apparaissent tout au long du projet
    subprocess.run(['rm','-f','report.txt'])
    os.system('node report.js > report.txt')

    # On réunit les informations concernant les issues
    subprocess.run(['rm','-f','issues.json'])
    os.system('node issues.js '+project+' > issues.json')

    # On combine les informations de traçage des smells et des bugs, et on enregistre un premier traçage des smells
    subprocess.run(['rm','-f','tracing_bugs.txt'])
    os.system('node combine.js > tracing_bugs.txt')

    # On trace les emplacements des bugs potentiels
    subprocess.run(['rm','-f','emplacements_bugs.txt'])
    os.system('python3 tracing_bugs_simple.py > emplacements_bugs.txt')

    # On trace les emplacements des bugs potentiels mais au sens large, en considérant les dépendances
    subprocess.run(['rm','-f','emplacements_bugs_large.txt'])
    os.system('python3 tracing_bugs_large.py > emplacements_bugs_large.txt')

    # On identifie les fichiers smelly
    subprocess.run(['python3','set_smelly.py'])

    # On remet en ordre les commits
    subprocess.run(['python3','commit_by_date.py'])

    # On revient dans le répertoire parent
    os.chdir('..')
    print()

    # On attend (pour éviter les erreur API rate limit)
    subprocess.run(['sleep','3600'])