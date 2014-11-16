import com.ibm.wala.types.*;
import com.ibm.wala.classLoader.*;
import com.ibm.wala.ipa.cha.*;
import com.ibm.wala.ipa.callgraph.*;
import com.ibm.wala.ipa.callgraph.impl.*;
import com.ibm.wala.ipa.callgraph.propagation.*;
import com.ibm.wala.ipa.callgraph.propagation.cfa.*;
import com.ibm.wala.ssa.*;

import com.ibm.wala.util.config.AnalysisScopeReader;

import java.util.*;
import java.util.jar.JarFile;
import java.io.File;


public class SampleAnalysis {
	private final String appPath = "C:/Users/Ahmed/workspace/wala_exercises/SampleApp/bin/classes";
    //private final String androidJarPath = "/home/michelle/android-sdk-linux/platforms/android-4.3/android.jar";
	private final String androidJarPath = "C:/Users/Ahmed/AppData/Local/Android/android-sdk/platforms/android-18/android.jar";
    private final String[] activityLifecycleMethods = {
        "onCreate(Landroid/os/Bundle;)V",
        "onStart()V",
        "onResume()V",
        "onPause()V",
        "onStop()V",
        "onRestart()V",
        "onDestroy()V"
    };

    public static void main(String[] args) {
        SampleAnalysis analysis = new SampleAnalysis();
        analysis.run(args);
    }

    public void run(String[] args) {
        try {
            AnalysisScope scope = getAnalysisScope();
            IClassHierarchy cha = ClassHierarchy.make(scope);

            System.out.println("Class Hierarchy");
            System.out.println("---------------");
            printClassHierarchy(cha, cha.getRootClass(), 0);
            System.out.println("======================");

            System.out.println("Lifecycle Methods");
            System.out.println("-----------------");
            printLifecycleMethods(cha);
            System.out.println("======================");

            List<Entrypoint> appEntrypoints = getAppEntrypoints(cha);
            CallGraph cg = makeZeroCFACallgraph(appEntrypoints, scope, cha);
            
            System.out.println("Call Graph");
            System.out.println("----------");
            printCallGraph(cg, cg.getFakeRootNode(), 0);
            System.out.println("======================");

            System.out.println("Malicious Behaviours");
            System.out.println("--------------------");
            printMaliciousBehaviours(cg);


        } catch (Exception e) {
            System.out.println("Exception: " + e);
            e.printStackTrace();
        }
    }

    private AnalysisScope getAnalysisScope() throws Exception {
        AnalysisScope scope = AnalysisScopeReader.makeJavaBinaryAnalysisScope(appPath, null);
        
        Module androidModule = new JarFileModule(new JarFile(androidJarPath));
        scope.addToScope(ClassLoaderReference.Extension, androidModule);

        return scope;
    }

    private void printClassHierarchy(IClassHierarchy cha, IClass currentClass, int level) {
        String indent = "";
        for (int i = 0; i < level; i++) {
            indent += "    ";
        }

        if (currentClass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
            System.out.println(indent + currentClass.getName().toString());
        }

        for (IClass subclass : cha.getImmediateSubclasses(currentClass)) {
            if (subclass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                printClassHierarchy(cha, subclass, level + 1);
            } else {
                printClassHierarchy(cha, subclass, level);
            }
        }
    }

    private void printLifecycleMethods(IClassHierarchy cha) {
        IClass activityClass = cha.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Extension, "Landroid/app/Activity"));

        for (IClass activitySubclass : cha.computeSubClasses(activityClass.getReference())) {
            if (!activitySubclass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                continue;
            }

            System.out.println("Activity class: " + activitySubclass.getName().toString());

            Collection<IMethod> declaredMethods = activitySubclass.getDeclaredMethods();
            //for (IMethod declaredMethod : declaredMethods) {
            //    System.out.println("    Declared: " + declaredMethod.getSignature());
            //}

            for (String lifecycle : activityLifecycleMethods) {
                IMethod lifecycleMethod = cha.resolveMethod(activitySubclass, Selector.make(lifecycle));
                if (declaredMethods.contains(lifecycleMethod)) {
                    System.out.println("    Lifecycle method: " + lifecycleMethod.getSignature());
                }
            }
        }
    }

    private void printCallGraph(CallGraph cg, CGNode currentNode, int level) {
        String indent = "";
        for (int i = 0; i < level; i++) {
            indent += "    ";
        }
        
        System.out.println(indent + currentNode.getMethod().getSignature());

        IClassHierarchy cha = cg.getClassHierarchy();
        Iterator<CallSiteReference> callsiteIter = currentNode.iterateCallSites();

        while (callsiteIter.hasNext()) {
            CallSiteReference callsite = callsiteIter.next();
            IMethod calledMethod = cha.resolveMethod(callsite.getDeclaredTarget());

            if (cg.getPossibleTargets(currentNode, callsite).isEmpty()) {
                System.out.println(indent + "    " + callsite.getDeclaredTarget().getSignature());
            } else {
                for (CGNode targetNode : cg.getPossibleTargets(currentNode, callsite)) {
                    if (targetNode.getMethod().getDeclaringClass().getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                        printCallGraph(cg, targetNode, level + 1);
                    } else {
                        System.out.println(indent + "    " + targetNode.getMethod().getSignature());
                    }
                }
            }
        }
    }

    private void printMaliciousBehaviours(CallGraph cg) {
        IClassHierarchy cha = cg.getClassHierarchy();
        String sendTextMessageSignature = "android.telephony.SmsManager.sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V";

        Iterator<CGNode> nodeIter = cg.iterator();

        while (nodeIter.hasNext()) {
            CGNode callerNode = nodeIter.next();

            Iterator<CallSiteReference> callSiteIter = callerNode.iterateCallSites();

            while (callSiteIter.hasNext()) {
                CallSiteReference callSite = callSiteIter.next();

                if (callSite.getDeclaredTarget().getSignature().equals(sendTextMessageSignature)) {
                    IR callerIR = callerNode.getIR();
                    SymbolTable callerSymbols = callerIR.getSymbolTable();
                    SSAInstruction invokeInstr = callerIR.getPEI(new ProgramCounter(callSite.getProgramCounter()));

                    if (callerSymbols.isStringConstant(invokeInstr.getUse(1))) {
                        System.out.println("Possible premium SMS to: " + callerSymbols.getStringValue(invokeInstr.getUse(1)));
                        
                        if (callerSymbols.isStringConstant(invokeInstr.getUse(3))) {
                            System.out.println("    text: " + callerSymbols.getStringValue(invokeInstr.getUse(3)));
                        } else {
                            DefUse callerDefUse = callerNode.getDU();
                            SSAInstruction textDefInstr = callerDefUse.getDef(invokeInstr.getUse(3));

                            if (textDefInstr != null) {
                                System.out.println("    text: " + textDefInstr.toString());
                            }
                        }
                    }
                }
            }
        }
    }

    private List<Entrypoint> getAppEntrypoints(IClassHierarchy cha) {
        List<Entrypoint> entrypoints = new ArrayList<Entrypoint>();

        // For now, just get lifecycle handlers
        IClass activityClass = cha.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Extension, "Landroid/app/Activity"));

        for (IClass activitySubclass : cha.computeSubClasses(activityClass.getReference())) {
            if (!activitySubclass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                continue;
            }

            Collection<IMethod> declaredMethods = activitySubclass.getDeclaredMethods();

            for (String lifecycle : activityLifecycleMethods) {
                IMethod lifecycleMethod = cha.resolveMethod(activitySubclass, Selector.make(lifecycle));

                if (declaredMethods.contains(lifecycleMethod)) {
                    entrypoints.add(new DefaultEntrypoint(lifecycleMethod, cha));
                }
            }
        }

        return entrypoints;
    }

    private CallGraph makeZeroCFACallgraph(Iterable<Entrypoint> entrypoints, AnalysisScope scope, IClassHierarchy cha) {
        try {
            AnalysisOptions options = new AnalysisOptions(scope, entrypoints);
            options.setSelector(new ClassHierarchyMethodTargetSelector(cha));
            options.setSelector(new ClassHierarchyClassTargetSelector(cha));

            SSAPropagationCallGraphBuilder builder = ZeroXCFABuilder.make(cha, options, new AnalysisCache(), new DefaultContextSelector(options, cha), null, ZeroXInstanceKeys.NONE);

            CallGraph cg = builder.makeCallGraph(options, null);
            return cg;

        } catch (Exception e) {
            System.out.println("Error: " + e.toString());
            return null;
        }
    }
}

