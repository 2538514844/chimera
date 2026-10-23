package dev.chimera.gradle;

import org.gradle.api.Plugin;
import org.gradle.api.Project;

/** Registers the 'chimeraObfuscate' task and the 'chimera' DSL extension. */
public final class ChimeraPlugin implements Plugin<Project> {
    @Override
    public void apply(Project project) {
        ChimeraExtension ext = project.getExtensions().create("chimera", ChimeraExtension.class);
        ext.nativeLibDir = project.getLayout().getBuildDirectory().dir("native-lib").get().getAsFile();
        project.getTasks().register("chimeraObfuscate", ChimeraObfuscateTask.class, task -> {
            task.setGroup("chimera");
            task.setDescription("Obfuscate the configured jar with Chimera");
            task.setExtension(ext);
        });
        project.getTasks().register("chimeraNativeCompile", ChimeraNativeCompileTask.class, task -> {
            task.setGroup("chimera");
            task.setDescription("Compile generated JNI .cpp templates into a native library with gcc/clang");
            task.setExtension(ext);
        });
    }
}
