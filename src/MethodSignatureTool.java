import com.ibm.wala.classLoader.*;
import com.ibm.wala.types.*;
import com.ibm.wala.ipa.cha.*;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.util.config.AnalysisScopeReader;

import java.util.*;
import java.util.regex.*;

public class MethodSignatureTool {
    private final String _androidLib = "/home/michelle/android-sdk-linux/platforms/android-4.3/android.jar";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: MethodSignatureTool <pattern string> ( --regex )");
            return;
        }

        String matchString = args[0];

        boolean regex = false;
        if (args.length > 1 && args[1].equals("--regex")) {
            regex = true;
        }

        MethodSignatureTool analysis = new MethodSignatureTool();
        analysis.run(matchString, regex);
    }

    public MethodSignatureTool() {
    }

    public void run(String matchString, boolean regex) throws Exception {
        AnalysisScope appScope = AnalysisScopeReader.makeJavaBinaryAnalysisScope(_androidLib, null);
        IClassHierarchy cha = ClassHierarchy.make(appScope);
        Pattern pattern = Pattern.compile(matchString);

        Iterator<IClass> classIter = cha.iterator();

        while (classIter.hasNext()) {
            IClass currentClass = classIter.next();

            for (IMethod currentMethod : currentClass.getDeclaredMethods()) {
                if ((!regex && currentMethod.getSignature().contains(matchString)) ||
                    (regex && pattern.matcher(currentMethod.getSignature()).matches())) {

                    System.out.println("Match: " + currentMethod.getSignature());
                    System.out.println("    Class:  " + currentClass.getName().toString());
                    System.out.println("    Method: " + currentMethod.getSelector().toString());
                }
            }
        }
    }
}

