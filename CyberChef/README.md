## CyberChef App

### Requirements
 - Node.js
 - NPM
 - Grunt-CLI (npm)

### Installation

1. Download CyberChef [https://github.com/gchq/CyberChef](https://github.com/gchq/CyberChef)
2. Build Cyberchef using the Grunt node task 
```
    grunt node
``` 
3. Copy resulting Cyberchef.js file into Cyberchef app.  Default is "./build/node/CyberChef.js"
4. Install production modules 
```
    npm install only=production
```
5. Copy node_modules folder into same location as CyberChef.js
