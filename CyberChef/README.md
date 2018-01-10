## CyberChef App

### Requirements
 - Node.js
 - These are only needed for building Cyberchef
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
- NPM > 3.3.0 
```
    npm install only=production
```
- NPM < 3.3.0
```
    npm install --production
```
5. Copy node_modules folder into same location as CyberChef.js
