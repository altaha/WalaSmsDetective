import com.ibm.wala.classLoader.*;
import com.ibm.wala.ssa.DefUse;
import com.ibm.wala.ssa.IR;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SymbolTable;
import com.ibm.wala.types.*;
import com.ibm.wala.ipa.cha.*;
import com.ibm.wala.ipa.callgraph.AnalysisCache;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.Entrypoint;
import com.ibm.wala.ipa.callgraph.impl.ClassHierarchyClassTargetSelector;
import com.ibm.wala.ipa.callgraph.impl.ClassHierarchyMethodTargetSelector;
import com.ibm.wala.ipa.callgraph.impl.DefaultContextSelector;
import com.ibm.wala.ipa.callgraph.impl.DefaultEntrypoint;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;
import com.ibm.wala.ipa.callgraph.propagation.cfa.ZeroXCFABuilder;
import com.ibm.wala.ipa.callgraph.propagation.cfa.ZeroXInstanceKeys;
import com.ibm.wala.util.config.AnalysisScopeReader;

import java.util.*;
import java.util.jar.JarFile;
import java.util.regex.*;

public class EntryPointsFinder {
    private final String _androidLib = "C:/Users/Ahmed/AppData/Local/Android/android-sdk/platforms/android-18/android.jar";
    //private final String appPath = "C:/Users/Ahmed/workspace/wala_exercises/SampleApp/bin/classes";
	//private final String appPath = "C:/Users/Ahmed/Desktop/Study_Stuff/MEng/ECE1776_Security/MalwareSamples/Gone60/Gone60Bin/com";
	//private final String appPath = "C:/Users/Ahmed/Desktop/Study_Stuff/MEng/ECE1776_Security/MalwareSamples/HippoSMS/HippoSMSBin/com";
	private final String appPath = "C:/Users/Ahmed/Desktop/Study_Stuff/MEng/ECE1776_Security/MalwareSamples/Zsone/ZsoneBin/com/mj";
    
    private Set<String> discoveredMethods;
    private Dictionary<String, IMethod> discoveredIMethodsDict;

    public static void main(String[] args) throws Exception {
    	
    	EntryPointsFinder finder = new EntryPointsFinder();
    	finder.run();
    }

    public EntryPointsFinder() {
    }

    public void run() throws Exception {
        //AnalysisScope appScope = AnalysisScopeReader.makeJavaBinaryAnalysisScope(_androidLib, null);
    	AnalysisScope appScope = AnalysisScopeReader.makeJavaBinaryAnalysisScope(appPath, null);
        Module androidModule = new JarFileModule(new JarFile(_androidLib));
        appScope.addToScope(ClassLoaderReference.Extension, androidModule);

        IClassHierarchy cha = ClassHierarchy.make(appScope);
        
    	discoveredMethods = new LinkedHashSet<String>();
    	discoveredIMethodsDict = new Hashtable<String, IMethod>();
        
        findAllMethods(cha);
        
        Set<String> entryPointsSignatures = findEntryPoints(appScope, cha);
        List<Entrypoint> entrypoints = new ArrayList<Entrypoint>();
        
        System.out.println("======= EntryPoint Signatures ======");
        Iterator<String> entryPointsIter = entryPointsSignatures.iterator();
        while(entryPointsIter.hasNext()) {
        	String entry = entryPointsIter.next();
        	System.out.println(entry);
        	entrypoints.add(new DefaultEntrypoint(this.discoveredIMethodsDict.get(entry), cha));
        }
        
    }
    
    private void findAllMethods(IClassHierarchy cha) throws Exception {
    	
    	Iterator<IClass> classIter = cha.iterator();

        while (classIter.hasNext()) {
            IClass currentClass = classIter.next();
            
            if (!currentClass.getClassLoader().getReference().equals(ClassLoaderReference.Application))
            	continue;
            
            System.out.println("Class: " + currentClass.getName().toString());

            for (IMethod currentMethod : currentClass.getDeclaredMethods()) {
            	System.out.println("    Method   : " + currentMethod.getSelector().toString());
            	System.out.println("    Signature: " + currentMethod.getSignature());
            	discoveredMethods.add(currentMethod.getSignature());
            	discoveredIMethodsDict.put(currentMethod.getSignature(), currentMethod);
            }
        }
        System.out.println("# of Methods found =  " + discoveredMethods.size());
    }
    
    private Set<String> findEntryPoints(AnalysisScope scope, IClassHierarchy cha) throws Exception {
    	
    	Set<String> supersetMethods = new LinkedHashSet<String>(this.discoveredMethods);
    	Set<String> entryPoints = new LinkedHashSet<String>();
    	
    	//iterate through all entries in discovered methods. Ad to entryPoints
    	//	For each create a call graph and traverse.
    	//	Remove all CG traversed methods from discoveredMethods and entryPoints if they exist there
    	//	At the end, entryPoints list should only contain methods that were never traversed in any CG
    	int i = 0;
    	while(!supersetMethods.isEmpty()) {
    		String nextmethod = supersetMethods.iterator().next();
    		supersetMethods.remove(nextmethod);
    		entryPoints.add(nextmethod);
    		
    		++i;
    		System.out.println("Creating call graph # " + i);
    		
    		//create a callgrph with nextmethod as the only entrypoint
    		List<Entrypoint> entrypoints = new ArrayList<Entrypoint>();
            entrypoints.add(new DefaultEntrypoint(this.discoveredIMethodsDict.get(nextmethod), cha));
    		CallGraph cg = makeZeroCFACallgraph(entrypoints, scope, cha);
    		
    		traverseCallGraph(nextmethod, cg, supersetMethods, entryPoints);
    	}
    	
    	return entryPoints;
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
    
    private void traverseCallGraph(String cgEntryMethod, CallGraph cg, Set<String> supersetMethods, Set<String> entryPoints) {

    	Iterator<CGNode> nodeIter = cg.iterator();
    	
    	while (nodeIter.hasNext()) {
            CGNode callerNode = nodeIter.next();

        /*    Iterator<CallSiteReference> callSiteIter = callerNode.iterateCallSites();

            while (callSiteIter.hasNext()) {
                CallSiteReference callSite = callSiteIter.next();
                
                String methodSig = callSite.getDeclaredTarget().getSignature();
                
                supersetMethods.remove(methodSig);
                entryPoints.remove(methodSig);
            }
        }*/
            IMethod methodI = callerNode.getMethod();
            String methodSig = callerNode.getMethod().getSignature();
            if (methodSig.equals(cgEntryMethod) ||
            	!methodI.getDeclaringClass().getClassLoader().getReference().equals(ClassLoaderReference.Application))
            	continue;

            System.out.println("Traversing: " + methodSig);
            supersetMethods.remove(methodSig);
            entryPoints.remove(methodSig);
        }
    }
}

