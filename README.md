# GitHub Advanced Security Featuring NodeGoat

## Please Read:

This repository exists as a way of demonstrating how GitHub Advanced Security fits within a development process in GitHub.  It is not meant to be built, deployed, hacked, or used in any kind of CTF.  It is a fork of the original NodeGoat.  If you want to try to learn how to hack NodeGoat, go here:
[ https://github.com/OWASP/NodeGoat ]

### Learn how GHAS integrates into a typical developer workflow.  To start, fork this repository.

### Enable Code Scanning
This repository does not have code scanning enabled.  Enable Code Scanning by going to Settings, and go to the Security and Analysis tab.  Click on the button that says "Set Up Code Scanning".  
There will be a section called "CodeQL Analysis".  Click on the button that says "Set up this workflow".
This will set up a GitHub Action in the file .github/workflows/codeql-analysis.yml
You can just accept all of the default options and commit this file.  Once this file is committed and pushed to main/master, the analysis will start, and the security findings will be published to the "Security" tab of this repository.

### Let's fix the code injection vulnerabilities.
  - In the "security" tab, click "Code scanning alerts", and find the Code Injection vulnerabilties.  There are three of them, but they all originate in the same file:  app/routes/contributions.js 
  - Select one, walk through the path by clicking "Show Path", and click on the file name to bring you to the line of code that is the source of the vulnerability.  
  - Change the branch to "Master" from the branch pull down list, and click the pencil icon to edit the file.  
  - Comment out lines 32, 33, and 34.  
  - Uncomment out lines 38, 39, and 40.
  - Create a branch and pull request, and click "Propose Changes".

This process will start the Code Scanning process.  All checks should pass, even though security vulnerabilities still exist.  This because this branch does not introduce any new vulnerabilities. Once all the checks pass, merge the changes.

This will start another code scanning process on the newly merged master branch.  Once the code scanning process is complete, then the three code injection vulnerabilities will close.

You can verify this by going into the code scanning alerts screen from the Security tab, and filtering for closed vulnerabilities.  

### Next, let's introduce a vulnerability.
  - Go to the file app/routes/profile.js
  - Comment out line 59
  - Uncomment out line 58
  - Create a new branch and pull request and click "Propose Changes".
  - This will start another code scanning process.  The check will fail because this branch introduces new security vulnerabilities, in this instance an "Inefficient Regular Expression".
  - Now you can fix the offending code by commenting out line 58 and un-commenting out line 59.
  - This will initiate a new scan, and the security vulnerabilities that were detected before should go away.


### Next, let's fix a vulnerable open source dependency. 
   - Go the Security tab and select "Dependabot Alerts"
   - Find the vulnerable package lodash with a high severity vulnerability, and select that.
   - Click "Create Dependabot security update"
   - A pull request will get created - this process may take some time.
   - Merge the pull request to close the dependabot alert.
   
## Advanced GHAS Concepts
The following steps are for security champions, DevSecops personnel or people interested in learning more about CodeQL as a language and tool for security research.
Before continuing, go to the  [VSCode CodeQL Starter Repo](https://github.com/github/vscode-codeql-starter).  
 - Follow the instructions in the README.md  there to install the Visual Studio Code extension and set up a starter project for developing your own CodeQL queries.
 - Download the [CodeQL CLI](https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/) so you will be able to create a CodeQL database of NodeGoat
 - Create a CodeQL Database for your version of the NodeGoat source code.
  - From the root of your Nodegoat source code directory Run the command:   codeql database create nodegoat-codeql-db --language=javascript
  - This will create a folder in your NodeGoat root source directory called "nodegoat-codeql-db"
 - In the Visual Studio CodeQL Starter Workspace you created in step one, enter the command pallette and type "CodeQL:"  Select "CodeQL:  Choose Database From Folder". 
 - Navigate to the database folder that was created, "nodegoat-codeql-db".
 - In Visual Studio Code, go to the CodeQL view.  In the "Databases" section, right click on the nodegoat database and select "Set Current Database"
 - Create a new file in the starter workspace called "sensitive-info.ql"
 - At the top of the file type "import java".  You're ready to begin.


### Let's hunt for more vulnerabilities:
  - Your organization wants to meet an industry regulation that states all sensitive user information must be encrypted.  The user data specification shows that social security number (SSN) and date of birth (DOB) are stored in a database. We can enforce this new regulation with CodeQL.
  - First, we have to find instances where sensitive info exists in the code.
  - Enter the following query into your sensitive-info.ql file: 
 ```
import javascript

from  PropAccess pa where pa.getPropertyName().toLowerCase().regexpMatch(".*ssn")
or pa.getPropertyName().toLowerCase().regexpMatch(".*dob")
select pa
```
  - Right click on anywhere in the file and select "CodeQL:  Run Query."  This will find all uses of sensitive information like social security number (SSN) and date of birth (DOB)
  - You should when user.ssn and user.dob get populated.  These need to be encrypted if they're going to get written to a database.  
  - Let's see if they get written to a database.  Re-write your query to read:
 ```
import javascript

from DatabaseAccess da
select da.asExpr()
```
  - You can see that through the users.update method call, that the dob and ssn are part of a user update.  But are they encrypted prior to the update?
  - In order to see if they're encrypted, we need to write a path query, to see if paths exist, from where the SSN or DOB are set in the user object to when they get written to the database without getting encrypted.  Here is the query to accomplish this:
```
/**
 * @name Sensitive Info Leak
 * @description sensitive info
 * @kind path-problem
 * @tags security
 *        external/cwe/311
 * @id sensitive-info
 * @problem.severity error
 */

import javascript
import DataFlow::PathGraph

//this taint tracking configuration tracks social security numbers
//and dates of birth that do not get encrypted in the database
class SensitiveInfoConfig extends TaintTracking::Configuration {
  SensitiveInfoConfig() { this = "SensitiveInfoConfig" }

  //a source is a variable  with ssn or dob
  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::ParameterNode v |
      v.getName().toLowerCase() in ["ssn", "dob"] and
      v = source
    )
  }

  //a sink is the user record used in a databaes update
  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode m | m.getAnArgument() = sink and m.getMethodName() = "update")
  }

  //help dataflow track from sensitive info to user record
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::PropWrite assn |
      assn.getBase().getALocalSource() = succ and
      pred = assn.getRhs()
    )
  }

  //a sanitizer is when the data is used as a parameter to the encrypt function
  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(DataFlow::MethodCallNode m |
      m.getAnArgument() = sanitizer and m.getMethodName() = "encrypt"
    )
  }
}

from SensitiveInfoConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Sensitive data Exposure"
```
Run this query, and you should see that the variables dob and ssn do not get encrypted prior to the database update.

### Let's add this query to the list of codeql queries we're going to automatically run
It's time to make sure these vulnerabilities get alerted to the developers.  
 - Save your sensitive-info.ql file as <repo root>/queries/sensitive-info.ql, and push it to your repo.
 - Update your .github/workflows/codeql-analysis.yml, starting at line 46 to read:
```
  with:
  languages: ${{ matrix.language }}
  queries: +security-extended, ./queries
```

When the code scan completes, a new security alert should be created, this one for your newly found sensitive info. 







 
