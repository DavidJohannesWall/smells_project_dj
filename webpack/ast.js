// Code pour extraire de l'AST (généré par uglifyjs) les informations concernant les appels de fonctions et de variables

// Uglifyjs permet de construire l'AST
var UglifyJS = require('uglify-js')
  , fs = require('fs')
// Le troisième argument de la ligne de commande correspond au fichier javaScript à parser
  , filename = process.argv[2];
//console.log(filename);
// On extrait le code de ce fichier
code = String(fs.readFileSync(filename));
// On construit l'AST de ce fichier
var Ast = UglifyJS.minify(code,{output : { ast : true, code : false},compress : {sequences : false}});

// data contiendra nos informations utiles (pour les variables et les functions)
data = {};
data["variables"] = {}
data["functions"] = {}

// L'ast n'est pas vide
if ('ast' in Ast) {
  // On stocke le nom de nos variables
  variables = Object.keys(Ast.ast.variables._values)
  //console.log("Voici les variables :",variables)

  // Pour chaque variables
  for (i = 0; i < variables.length; i++) {
    // On initialise "Orig" qui contiendra les lignes d'initialisation, et "References" qui contiendra les lignes d'appel
    data["variables"][variables[i]] = {"Orig":[],"References":[]}
    // On stocke la ligne de début d'initialisation
    data["variables"][variables[i]]["Orig"].push(Ast.ast.variables._values[variables[i]].orig[0].start.line)
    // Fin contiendra la ligne de fin d'initialisation
    fin = null
    // On regarde le corps de l'AST
    for (j=0; j<Ast.ast.body.length; j++) {
      // Si un des AST_Node contient la clé "definitions"
      if('definitions' in Ast.ast.body[j]) {
        // Alors on regarde les définitions présentes
        for (k=0; k<Ast.ast.body[j].definitions.length; k++) {
          // Si une des définitions correspond à une variable qui a le même nom que celle étudiée
          if(Ast.ast.body[j].definitions[k].name.name == Ast.ast.variables._values[variables[i]].name) {
            // Alors on stocke la ligne de fin d'initialisation de la variable
            fin = Ast.ast.body[j].definitions[k].end.endline
          }
        }
      }
    }
    // On stocke cette ligne de fin
    data["variables"][variables[i]]["Orig"].push(fin)

    // On regarde à chaque fois que la variable est ensuite appelée (référencée)
    for (j=0; j<Ast.ast.variables._values[variables[i]].references.length; j++) {
      // On stocke les lignes de début et de fin d'appel de cette variable
      data["variables"][variables[i]]["References"].push([Ast.ast.variables._values[variables[i]].references[j].start.line,Ast.ast.variables._values[variables[i]].references[j].end.line])
    }

    // Si fin est nulle, cela signifie que la variable étudiée était une fonction. On la supprime donc du dictionnaire data.
    if(fin == null) {
      delete data["variables"][variables[i]]
    }
  }

  // On stocke le nom de nos fonctions
  functions = Object.keys(Ast.ast.functions._values)
  //console.log("Voici les fonctions :",functions)

  // Pour chaque fonction
  for (i = 0; i < functions.length; i++) {
    // On initialise "Orig" qui contiendra les lignes d'initialisation, et "References" qui contiendra les lignes d'appel
    data["functions"][functions[i]] = {"Orig":[],"References":[]}
    // On stocke la ligne de début d'initialisation
    data["functions"][functions[i]]["Orig"].push(Ast.ast.functions._values[functions[i]].orig[0].start.line)
    // Fin contiendra la ligne de fin d'initialisation
    fin = null
    // On regarde le corps de l'AST
    for (j=0; j<Ast.ast.body.length; j++) {
      // Si un des AST_Node contient la clé "name", et que le nom de la fonction correspond au nom de la fonction étudiée
      if('name' in Ast.ast.body[j] && Ast.ast.body[j].name.name == Ast.ast.functions._values[functions[i]].name) {
        // On stocke la ligne de fin d'initialisation de la fonction
        fin = Ast.ast.body[j].end.endline
      }
    }
    // On stocke cette ligne de fin
    data["functions"][functions[i]]["Orig"].push(fin)

    // On regarde à chaque fois que la fonction est ensuite appelée (référencée)
    for (j=0; j<Ast.ast.functions._values[functions[i]].references.length; j++) {
      // On stocke les lignes de début et de fin d'appel de cette fonction
      data["functions"][functions[i]]["References"].push([Ast.ast.functions._values[functions[i]].references[j].start.line,Ast.ast.functions._values[functions[i]].references[j].end.endline])
    }
  }
}

// On écrit dans un JSON notre dictionnaire data
fs.writeFileSync('./ast.json', JSON.stringify(data));