package dev.chimera.transform.indy;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Offline M10 scan utility (not a JUnit test). Runs {@link IndyIntegration#prepare} on every class
 * of a jar (conservative vs aggressive), prints rewrite/skip statistics, member-table size and
 * structural validation results. It never loads classes and never starts a client.
 *
 * <pre>java -cp ... dev.chimera.transform.indy.WurstIndyScan path/to/client.jar</pre>
 */
public final class WurstIndyScan {

    private WurstIndyScan() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: WurstIndyScan <jar>");
            System.exit(2);
        }
        Path jar = Path.of(args[0]);
        if (!Files.isRegularFile(jar)) {
            System.err.println("jar not found: " + jar);
            System.exit(2);
        }

        Map<String, byte[]> classes = new LinkedHashMap<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                if (entry.getName().endsWith("module-info.class")) {
                    continue;
                }
                try (InputStream in = zip.getInputStream(entry)) {
                    classes.put(entry.getName(), in.readAllBytes());
                }
            }
        }

        int existingIndy = 0;
        int existingIndyClasses = 0;
        for (byte[] bytes : classes.values()) {
            int indy = countExistingIndy(bytes);
            existingIndy += indy;
            if (indy > 0) {
                existingIndyClasses++;
            }
        }

        IndyIntegration.Result conservative = IndyIntegration.prepare(classes, IndyIntegration.Options.CONSERVATIVE);
        IndyIntegration.Result aggressive = IndyIntegration.prepare(classes, IndyIntegration.Options.AGGRESSIVE);

        System.out.println("# M10 Wurst indy scan (IndyIntegration)");
        System.out.println("jar=" + jar.toAbsolutePath());
        System.out.println("jarBytes=" + Files.size(jar));
        System.out.println("classEntries=" + classes.size());
        System.out.println("existingIndySites=" + existingIndy);
        System.out.println("existingIndyClasses=" + existingIndyClasses);
        printResult("conservative", conservative, classes.size());
        printResult("aggressive", aggressive, classes.size());

        int validationFailures = 0;
        List<String> failures = new ArrayList<>();
        for (Map.Entry<String, byte[]> entry : aggressive.classes().entrySet()) {
            try {
                new ClassReader(entry.getValue())
                        .accept(new CheckClassAdapter(new ClassWriter(0), false), 0);
            } catch (Throwable t) {
                validationFailures++;
                if (failures.size() < 10) {
                    failures.add(entry.getKey() + " -> " + t.getClass().getSimpleName()
                            + ": " + t.getMessage());
                }
            }
        }
        System.out.println("validationFailures=" + validationFailures);
        for (String failure : failures) {
            System.out.println("  failure=" + failure);
        }

        List<Map.Entry<String, Integer>> ranked = new ArrayList<>();
        for (Map.Entry<String, byte[]> entry : aggressive.classes().entrySet()) {
            int count = countIndy(entry.getValue());
            if (count > 0) {
                ranked.add(Map.entry(entry.getKey(), Integer.valueOf(count)));
            }
        }
        ranked.sort(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder())
                .thenComparing(Map.Entry.comparingByKey()));
        System.out.println("topClasses:");
        for (int i = 0; i < Math.min(10, ranked.size()); i++) {
            System.out.println("  " + ranked.get(i).getKey() + "=" + ranked.get(i).getValue());
        }
    }

    private static void printResult(String label, IndyIntegration.Result result, int classCount) {
        IndyDispatchTransformer.Stats stats = result.stats();
        System.out.println("--- " + label + " ---");
        System.out.println("classesWithRewrite=" + stats.classesWithRewrite() + "/" + classCount);
        System.out.println("invokeSites=" + stats.invokeSites());
        System.out.println("rewritten=" + stats.rewritten());
        System.out.println("rewrittenPct=" + percent(stats.rewritten(), stats.invokeSites()));
        System.out.println("skipped=" + stats.skipped());
        System.out.println("rewrittenStatic=" + stats.rewrittenStatic());
        System.out.println("rewrittenVirtual=" + stats.rewrittenVirtual());
        System.out.println("rewrittenInterface=" + stats.rewrittenInterface());
        System.out.println("rewrittenSpecial=" + stats.rewrittenSpecial());
        System.out.println("memberEntries=" + result.memberEntries());
        System.out.println("classEntries=" + result.classEntries());
        System.out.println("memberTableBytes=" + result.memberTable().length);
        System.out.println("preservedMixinClasses=" + result.preservedMixinClasses());
        for (Map.Entry<String, Integer> reason : stats.skipDistribution().entrySet()) {
            System.out.println("skip." + reason.getKey() + "=" + reason.getValue());
        }
    }

    private static int countExistingIndy(byte[] classBytes) {
        return countIndy(classBytes);
    }

    private static int countIndy(byte[] classBytes) {
        ClassNode node = new ClassNode();
        new ClassReader(classBytes).accept(node, 0);
        int count = 0;
        for (var method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof InvokeDynamicInsnNode) {
                    count++;
                }
            }
        }
        return count;
    }

    private static String percent(int part, int whole) {
        if (whole == 0) {
            return "0.00";
        }
        return String.format(java.util.Locale.ROOT, "%.2f", part * 100.0 / whole);
    }
}
