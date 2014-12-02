import com.ibm.wala.types.*;
import com.ibm.wala.classLoader.*;
import com.ibm.wala.ipa.cha.*;
import com.ibm.wala.ipa.callgraph.*;
import com.ibm.wala.ipa.callgraph.impl.*;
import com.ibm.wala.ipa.callgraph.propagation.*;
import com.ibm.wala.ipa.callgraph.propagation.cfa.*;
import com.ibm.wala.ssa.*;
import com.ibm.wala.util.config.AnalysisScopeReader;
import com.ibm.wala.ipa.slicer.Statement;
import com.ibm.wala.ipa.slicer.Slicer;
import com.ibm.wala.ipa.slicer.Slicer.DataDependenceOptions;
import com.ibm.wala.ipa.slicer.Slicer.ControlDependenceOptions;
//import com.ibm.wala.util.strings.Atom;
//import com.ibm.wala.util.debug.Assertions;


import java.util.*;
import java.util.jar.JarFile;
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;


public class AnalysisFromEntrypoints {
	private final String appPath = "C:/Users/Ahmed/Desktop/Study_Stuff/MEng/ECE1776_Security/MalwareSamples/HippoSMS/HippoSMSBin/com";
	private final String androidJarPath = "C:/Users/Ahmed/AppData/Local/Android/android-sdk/platforms/android-18/android.jar";
	private final String entrypoints_FilePath = "C:/Users/Ahmed/Desktop/Study_Stuff/MEng/ECE1776_Security/MalwareSamples/HippoSMS/entries.txt";
	
	private static final int Send_Threat = 1;
	private static final int Recv_Threat = 2;
	private static final int All_Threats = 3;

    private Set<String> discoveredMethods;
    private Dictionary<String, IMethod> discoveredIMethodsDict;
	
	private Set<String> cgset;

    public static void main(String[] args) {
        AnalysisFromEntrypoints analysis = new AnalysisFromEntrypoints();
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
            
			String entrypointsFilePath = entrypoints_FilePath;
            if (args.length > 1)
            	entrypointsFilePath = args[1];
            System.out.println("Reading Entry Points from: " + entrypointsFilePath);
            
            int threat_type = All_Threats;
            if (args.length > 2)
            	threat_type = Integer.parseInt(args[2]);
            System.out.println("Detecting Threat Type: " + threat_type);


            AnalysisScope scope = getAnalysisScope(app_path);
            IClassHierarchy cha = ClassHierarchy.make(scope);

            System.out.println("Class Hierarchy");
            System.out.println("---------------");
            printClassHierarchy(cha, cha.getRootClass(), 0);
            System.out.println("======================");

            System.out.println("Lifecycle Methods");
            System.out.println("-----------------");
            List<Entrypoint> appEntrypoints = readEntryPoints(cha, entrypointsFilePath);
            System.out.println("======================");

            // Create Call Graph builder
            System.out.println("Call Graph");
            System.out.println("----------");
            AnalysisOptions options = new AnalysisOptions(scope, appEntrypoints);
            options.setSelector(new ClassHierarchyMethodTargetSelector(cha));
            options.setSelector(new ClassHierarchyClassTargetSelector(cha));

            SSAPropagationCallGraphBuilder builder = ZeroXCFABuilder.make(cha, options, new AnalysisCache(), new DefaultContextSelector(options, cha), null, ZeroXInstanceKeys.NONE);

            CallGraph cg = builder.makeCallGraph(options, null);
            PointerAnalysis pa = builder.getPointerAnalysis();


            printCallGraph(cg, cg.getFakeRootNode(), 0);
            System.out.println("======================");

            System.out.println("Malicious Behaviours");
            if ((threat_type & Send_Threat) > 0) {
            	System.out.println("-----SMS SEND-------");
            	ret |= printMaliciousBehavioursSend(cg, pa);
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

    private int printMaliciousBehavioursSend(CallGraph cg, PointerAnalysis pa) throws Exception {
    	int ret = 0;
        String sendTextMessageSignature = "android.telephony.SmsManager.sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V";
        String sendTextMessageSignature2 = "android.telephony.gsm.SmsManager.sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V";

        Iterator<CGNode> nodeIter = cg.iterator();

        while (nodeIter.hasNext()) {
            CGNode callerNode = nodeIter.next();

            Iterator<CallSiteReference> callSiteIter = callerNode.iterateCallSites();

            while (callSiteIter.hasNext()) {
                CallSiteReference callSite = callSiteIter.next();

                if (callSite.getDeclaredTarget().getSignature().equals(sendTextMessageSignature) ||
                		callSite.getDeclaredTarget().getSignature().equals(sendTextMessageSignature2)) {
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
                    } else {
                    	System.out.println("Trying Slicer based detection");
                    	Statement statement = findCallTo(callerNode, "sendTextMessage");
                    	
                    	Collection<Statement> slice;
                        // context-sensitive thin slice
                        slice = Slicer.computeBackwardSlice(statement, cg, pa, DataDependenceOptions.NO_BASE_PTRS,
                            ControlDependenceOptions.NONE);
                        for (Statement s : slice){
                        	CGNode slicenode = s.getNode();
                        	System.out.println(s);
                        }
                    }
                }
            }
        }
        return ret;
    }
    
    private Boolean foundRecv;
    private Boolean foundAbort;

    private int printMaliciousBehavioursRecv(CallGraph cg, CGNode currentNode) {
    	int ret = 0;
    	
    	foundRecv = false;
        foundAbort = false;
        
        String methodSig = currentNode.getMethod().getSignature();
        this.cgset.add(methodSig);

        IClassHierarchy cha = cg.getClassHierarchy();
        Iterator<CallSiteReference> callsiteIter = currentNode.iterateCallSites();

        while (callsiteIter.hasNext()) {
            CallSiteReference callsite = callsiteIter.next();
            IMethod calledMethod = cha.resolveMethod(callsite.getDeclaredTarget());

            if (cg.getPossibleTargets(currentNode, callsite).isEmpty()) {
            	//TODO:
                //System.out.println("    " + callsite.getDeclaredTarget().getSignature());
            	methodSig = callsite.getDeclaredTarget().getSignature();
            	ret |= receiveMalwareDetectionChecks(methodSig);
            	
            } else {
                for (CGNode targetNode : cg.getPossibleTargets(currentNode, callsite)) {
                	
                	methodSig = targetNode.getMethod().getSignature();
                	
                    if (targetNode.getMethod().getDeclaringClass().getClassLoader().getReference().equals(ClassLoaderReference.Application)
                    		&& !this.cgset.contains(methodSig)) {
                    	ret |= printMaliciousBehavioursRecv(cg, targetNode);
                    } else {
                    	ret |= receiveMalwareDetectionChecks(methodSig);
                    }
                }
            }
        }
        return ret;
    }
    
    private int receiveMalwareDetectionChecks(String methodSig) {
    	int ret = 0;
    	
        String recvTextMessageSignature1 = "android.telephony.gsm.SmsMessage.createFromPdu([B)Landroid/telephony/gsm/SmsMessage;";
        String recvTextMessageSignature2 = "android.telephony.SmsMessage.createFromPdu([B)Landroid/telephony/SmsMessage;";
        String sendTextMessageSignature = "android.telephony.SmsManager.sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V";
        String sendTextMessageSignature2 = "android.telephony.gsm.SmsManager.sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V";
        String abortBroadcastSignature = "android.content.BroadcastReceiver.abortBroadcast()V";
    	
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
        else if (methodSig.equals(sendTextMessageSignature) ||
        		methodSig.equals(sendTextMessageSignature2)) {
        	System.out.println("Yayyy Found a Send Message");
        	if (foundRecv) {
        		System.out.println("Detected Recv Malware (3)");
        		ret = Recv_Threat;
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
    
    private List<Entrypoint> readEntryPoints(IClassHierarchy cha, String infile) throws Exception {

    	//read entrypoint signatures from infile
    	List<String> entrypointSignatures = new ArrayList<String>();
    	FileInputStream fstream = new FileInputStream(infile);
    	BufferedReader br = new BufferedReader(new InputStreamReader(new DataInputStream(fstream)));
    	String strLine;
    	while ((strLine = br.readLine()) != null){
    		entrypointSignatures.add(strLine);
    	}
    	br.close();


    	//resolve entrypoint signatures into IMethods
    	List<Entrypoint> entrypoints = new ArrayList<Entrypoint>();
    	
    	for (String entrySignature: entrypointSignatures) {
	    	
    		Iterator<IClass> classIter = cha.iterator();
	        while (classIter.hasNext()) {
	            IClass currentClass = classIter.next();
	            
	            if (!currentClass.getClassLoader().getReference().equals(ClassLoaderReference.Application))
	            	continue;
	
	            for (IMethod currentMethod : currentClass.getDeclaredMethods()) {
	            	if (currentMethod.getSignature().equals(entrySignature)) {
	            		System.out.println("Found Method for Signature: " + entrySignature);
	            		entrypoints.add(new DefaultEntrypoint(currentMethod, cha));
	            	}
	            }
	        }
    	}
        System.out.println("# of entrypoints read =  " + entrypoints.size());
        return entrypoints;
    }
    
    public static Statement findCallTo(CGNode n, String methodName) {
        IR ir = n.getIR();
        for (Iterator<SSAInstruction> it = ir.iterateAllInstructions(); it.hasNext();) {
          SSAInstruction s = it.next();
          if (s instanceof com.ibm.wala.ssa.SSAAbstractInvokeInstruction) {
            com.ibm.wala.ssa.SSAAbstractInvokeInstruction call = (com.ibm.wala.ssa.SSAAbstractInvokeInstruction) s;
            if (call.getCallSite().getDeclaredTarget().getName().toString().equals(methodName)) {
              com.ibm.wala.util.intset.IntSet indices = ir.getCallInstructionIndices(call.getCallSite());
              com.ibm.wala.util.debug.Assertions.productionAssertion(indices.size() == 1, "expected 1 but got " + indices.size());
              return new com.ibm.wala.ipa.slicer.NormalStatement(n, indices.intIterator().next());
            }
          }
        }
        return null;
    }
}

