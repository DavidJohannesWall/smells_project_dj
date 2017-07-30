import json
from urllib.request import urlopen
import re

# On stocke les commits rangés par ordre croissant de date
with open("commit_epoque.json") as json_data:
    data = json.load(json_data)
    json_data.close()

# On inverse le dictionnaire data
inv_data = {data[k]:k for k in data if k != "undefined"}

# Pour chaque commit (par odre croissant de date), on fait une requête pour savoir les vulnérabilités présentes dans ce commit
for i in range(1,len(inv_data)+1):
    # Certains commits ne sont pas répertoriés, donc on fait un try pour laisser passer l'erreur 404
    try:
        # On stocke l'url par lequel on fait la requête (nom_répertoire/nom_projet/numéro_commit)
        url_ = 'https://snyk.io/test/github/request/request/'+inv_data[i]
        # On stocke la réponse de la requête
        response = urlopen(url_)
        # On transforme en chaîne de caractère la réponse
        string = response.read().decode('utf-8')
        # On stocke le nombre de vulnérabilités présentes dans le commit
        nb_vulnerabilities = string.split('Known vulnerabilities</span><span>')[1].split('</span>')[0]
        # On affiche l'époque du commit, l'identifiant du commit, et le nombre de vulnérabilités présentes dans le commit
        print('Epoque :',i)
        print('Commit :',inv_data[i])
        print('Nombre de vulnérabilités :',nb_vulnerabilities)
        # Pour chaque vulnérabilité
        for j in range(1,int(nb_vulnerabilities)+1):
            # On stocke les informations concernant cette vulnérabilité
            vulnerability = string.split('<h2 class="card__title">')[j]
            # On stocke le titre de la vulnérabilité
            title = vulnerability.split('</h2>')[0]
            # On stocke le module vulnérable
            module = re.sub('\n','',vulnerability.split("Vulnerable module:")[1]).split('</li>')[0].strip()
            # On stocke les informations d'introduction de la vulnérabilité
            introducing = re.sub('\n','',vulnerability.split("Introduced through:")[1]).split('</li>')[0].strip()
            # On affiche les informations concernant cette vulnérabilité (quel vulnérabilité, titre, module, introduction)
            print('Vulnerability',j)
            print('Title :',title)
            print('Vulnerable module :',module)
            print('Introducing through :',introducing)
        print()
    # En cas d'exception (erreur 404), on passe...
    except:
        #print('Epoque :',i)
        #print('Commit :',inv_data[i])
        #print('Nombre de vulnérabilités : NOT FOUND')
        #print()
        pass