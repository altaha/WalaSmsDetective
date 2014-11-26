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
	private final String androidJarPath = "C:/Users/Ahmed/AppData/Local/Android/android-sdk/platforms/android-18/android.jar";

	private final String[] activityLifecycleMethods = {
		"onCreate(Landroid/os/Bundle;)V",
		"onStart()V",
		"onResume()V",
		"onPause()V",
		"onStop()V",
		"onRestart()V",
		"onDestroy()V",
		"onItemClick(Landroid/widget/AdapterView;Landroid/view/View;IJ)V",
	};
	private final String[] activityTypeName = {"Landroid/app/Activity"};

	private final String[] bcastRecvLifecycleMethods = {
		"onReceive(Landroid/content/Context;Landroid/content/Intent;)V",
	};
	private final String[] bcastRecvTypeName = {"Landroid/content/BroadcastReceiver"};
	
	private final String[] serviceLifecycleMethods = {
		"onCreate()V",
		"onDestroy()V",
		"onBind(Landroid/content/Intent;)V",
		"onStart(Landroid/content/Intent;I)V",
	};
	private final String[] serviceTypeName = {"Landroid/app/Service"};

	private static final int Activity_Analysis = 0x1;
	private static final int BcastRecv_Analysis = 0x2;
	private static final int Service_Analysis = 0x4;
	private static final int All_Analysis = 0x1000;
	
	private static final int Send_Threat = 1;
	private static final int Recv_Threat = 2;
	private static final int All_Threats = 3;
	
	private Set<String> cgset;

    public static void main(String[] args) {
        SampleAnalysis analysis = new SampleAnalysis();
        int ret = analysis.run(args);
        System.exit(ret);
    }

    public int run(String[] args) {
    	int ret = 0;
    	
		try {
			String app_path = appPath;
            if (args.length > 0)
				app_path = args[0];
            System.out.println("Analysing App_Path: " + app_path);
            
            int component_type = All_Analysis;
            if (args.length > 1)
				component_type = Integer.parseInt(args[1]);
            System.out.println("Analysing Component Type: " + component_type);
            
            int threat_type = All_Threats;
            if (args.length > 2)
            	threat_type = Integer.parseInt(args[2]);
            System.out.println("Detecting Threat Type: " + threat_type);
            
            String[] LifecycleMethods;
            String[] AnalysisTypeNames;
            if (component_type == Activity_Analysis) {
            	LifecycleMethods = activityLifecycleMethods;
            	AnalysisTypeNames = activityTypeName;
            } else if (component_type == BcastRecv_Analysis) {
            	LifecycleMethods = bcastRecvLifecycleMethods;
            	AnalysisTypeNames = bcastRecvTypeName;
            } else if (component_type == Service_Analysis) {
            	LifecycleMethods = serviceLifecycleMethods;
            	AnalysisTypeNames = serviceTypeName;
            	
            } else { // COmbine all types
            	LifecycleMethods = concatStrings(activityLifecycleMethods, bcastRecvLifecycleMethods);
            	LifecycleMethods = concatStrings(LifecycleMethods, serviceLifecycleMethods);
            	
            	AnalysisTypeNames = concatStrings(activityTypeName, bcastRecvTypeName);            	
            	AnalysisTypeNames = concatStrings(AnalysisTypeNames, serviceTypeName);
            }

            AnalysisScope scope = getAnalysisScope(app_path);
            IClassHierarchy cha = ClassHierarchy.make(scope);

            System.out.println("Class Hierarchy");
            System.out.println("---------------");
            printClassHierarchy(cha, cha.getRootClass(), 0);
            System.out.println("======================");

            System.out.println("Lifecycle Methods");
            System.out.println("-----------------");
            List<Entrypoint> appEntrypoints = printLifecycleMethods(cha, AnalysisTypeNames, LifecycleMethods);
            System.out.println("======================");

            // Create Call Graph builder
            CallGraph cg = makeZeroCFACallgraph(appEntrypoints, scope, cha);
            
            System.out.println("Call Graph");
            System.out.println("----------");
            //printCallGraph(cg, cg.getFakeRootNode(), 0);
            System.out.println("======================");

            System.out.println("Malicious Behaviours");
            if ((threat_type & Send_Threat) > 0) {
            	System.out.println("-----SMS SEND-------");
            	ret |= printMaliciousBehavioursSend(cg);
            }
            if ((threat_type & Recv_Threat) > 0) {
            	System.out.println("-----SMS RECV-------");
            	this.cgset = new HashSet<String>(); //reset the set of iterated nodes
            	ret |= printMaliciousBehavioursRecv(cg, cg.getFakeRootNode());
            }

        } catch (Exception e) {
            System.out.println("Exception: " + e);
            e.printStackTrace();
        }
        return ret;
    }

    private AnalysisScope getAnalysisScope(String app_path) throws Exception {
        AnalysisScope scope = AnalysisScopeReader.makeJavaBinaryAnalysisScope(app_path, null);
        
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

    private List<Entrypoint> printLifecycleMethods(IClassHierarchy cha, String[] typeNames, String[] lifecycleMethods) {
        List<Entrypoint> entrypoints = new ArrayList<Entrypoint>();

        for (String typeName : typeNames) {
        	
        	System.out.println("=== Finding EntryPoints for " + typeName + " class ===");

	        IClass activityClass = cha.lookupClass(TypeReference.findOrCreate(ClassLoaderReference.Extension, typeName));
	
	        for (IClass activitySubclass : cha.computeSubClasses(activityClass.getReference())) {
	            if (!activitySubclass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
	                continue;
	            }
	
	            System.out.println(typeName + " class: " + activitySubclass.getName().toString());
	
	            Collection<IMethod> declaredMethods = activitySubclass.getDeclaredMethods();
	            //for (IMethod declaredMethod : declaredMethods) {
	            //    System.out.println("    Declared: " + declaredMethod.getSignature());
	            //}
	
	            for (String lifecycle : lifecycleMethods) {
	                IMethod lifecycleMethod = cha.resolveMethod(activitySubclass, Selector.make(lifecycle));
	                if (declaredMethods.contains(lifecycleMethod)) {
	                    System.out.println("    Lifecycle method: " + lifecycleMethod.getSignature());
	                    entrypoints.add(new DefaultEntrypoint(lifecycleMethod, cha));
	                }
	            }
	        }
        }

        return entrypoints;
    }

    private void printCallGraph(CallGraph cg, CGNode currentNode, int level) {
        String indent = "";
        for (int i = 0; i < level; i++) {
            indent += "    ";
        }
        if (level == 0)
        	this.cgset = new HashSet<String>();
        
        String methodSig = currentNode.getMethod().getSignature();
        System.out.println(indent + methodSig);
        
        this.cgset.add(methodSig);

        IClassHierarchy cha = cg.getClassHierarchy();
        Iterator<CallSiteReference> callsiteIter = currentNode.iterateCallSites();

        while (callsiteIter.hasNext()) {
            CallSiteReference callsite = callsiteIter.next();
            IMethod calledMethod = cha.resolveMethod(callsite.getDeclaredTarget());

            if (cg.getPossibleTargets(currentNode, callsite).isEmpty()) {
            	methodSig = callsite.getDeclaredTarget().getSignature();
                System.out.println(indent + "    " + methodSig);
            } else {
                for (CGNode targetNode : cg.getPossibleTargets(currentNode, callsite)) {
                	methodSig = targetNode.getMethod().getSignature();
                    if (targetNode.getMethod().getDeclaringClass().getClassLoader().getReference().equals(ClassLoaderReference.Application) &&
                    		!this.cgset.contains(methodSig)) {
                        printCallGraph(cg, targetNode, level + 1);
                    } else {
                        System.out.println(indent + "    " + methodSig);
                    }
                }
            }
        }
    }

    private int printMaliciousBehavioursSend(CallGraph cg) {
    	int ret = 0;
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
                        ret = Send_Threat;
                        
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
        return ret;
    }

    private int printMaliciousBehavioursRecv(CallGraph cg, CGNode currentNode) {
    	int ret = 0;
        String recvTextMessageSignature1 = "android.telephony.gsm.SmsMessage.createFromPdu([B)Landroid/telephony/gsm/SmsMessage;";
        String recvTextMessageSignature2 = "android.telephony.SmsMessage.createFromPdu([B)Landroid/telephony/SmsMessage;";
        String abortBroadcastSignature = "android.content.BroadcastReceiver.abortBroadcast()V";
        
        String methodSig = currentNode.getMethod().getSignature();
        this.cgset.add(methodSig);

        IClassHierarchy cha = cg.getClassHierarchy();
        Iterator<CallSiteReference> callsiteIter = currentNode.iterateCallSites();
        
        Boolean foundRecv = false;
        Boolean foundAbort = false;

        while (callsiteIter.hasNext()) {
            CallSiteReference callsite = callsiteIter.next();
            IMethod calledMethod = cha.resolveMethod(callsite.getDeclaredTarget());

            if (cg.getPossibleTargets(currentNode, callsite).isEmpty()) {
            	//TODO: What does below statement do?
                //System.out.println("    " + callsite.getDeclaredTarget().getSignature());
            } else {
                for (CGNode targetNode : cg.getPossibleTargets(currentNode, callsite)) {
                	
                	methodSig = targetNode.getMethod().getSignature();
                	
                    if (targetNode.getMethod().getDeclaringClass().getClassLoader().getReference().equals(ClassLoaderReference.Application)
                    		&& !this.cgset.contains(methodSig)) {
                    	ret = printMaliciousBehavioursRecv(cg, targetNode);
                    } else {
                        if (methodSig.equals(recvTextMessageSignature1)
                        	|| methodSig.equals(recvTextMessageSignature2)) {
                            System.out.println("Yayyy Found an SMS Receive");;
                            foundRecv = true;
                            if (foundAbort) {
                        		System.out.println("Detected Recv Malware (1)");
                        		ret = Recv_Threat;
                            }
                        }
                        else if (methodSig.equals(abortBroadcastSignature)) {
                        	System.out.println("Yayyy Found a Broadcast abort");
                        	foundAbort = true;
                        	if (foundRecv) {
                        		System.out.println("Detected Recv Malware (2)");
                        		ret = Recv_Threat;
                        	}
                        }
                    }
                }
            }
        }
        return ret;
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
    
    public static String[] concatStrings(String[] A, String[] B) {
 	   int aLen = A.length;
 	   int bLen = B.length;
 	   String[] C= new String[aLen+bLen];
 	   System.arraycopy(A, 0, C, 0, aLen);
 	   System.arraycopy(B, 0, C, aLen, bLen);
 	   return C;
 	}
}

