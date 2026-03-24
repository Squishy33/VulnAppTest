/**
 * @name SQL Injection vulnerability (OWASP A03:2021 - Injection)
 * @description Detects SQL queries built using string concatenation,
 *              which may allow SQL injection attacks.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @id java/sql-injection-simple
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/owasp-a03
 */

import java

from MethodCall call, Expr arg
where
  (
    call.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.sql", "Statement") and
    call.getMethod().getName().regexpMatch("execute.*")
    or
    call.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.sql", "Connection") and
    call.getMethod().getName() = "prepareStatement"
  ) and
  arg = call.getArgument(0) and
  arg instanceof AddExpr
select call, "Possible SQL injection: SQL query is built with string concatenation."
