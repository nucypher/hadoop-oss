package com.nucypher.prkeyrotation;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.server.namenode.NuCypherExtRpcServer;
import org.apache.hadoop.yarn.api.ApplicationConstants;
import org.apache.hadoop.yarn.api.ApplicationConstants.Environment;
import org.apache.hadoop.yarn.api.records.*;
import org.apache.hadoop.yarn.client.api.YarnClient;
import org.apache.hadoop.yarn.client.api.YarnClientApplication;
import org.apache.hadoop.yarn.conf.YarnConfiguration;
import org.apache.hadoop.yarn.util.Apps;
import org.apache.hadoop.yarn.util.ConverterUtils;
import org.apache.hadoop.yarn.util.Records;

import static org.apache.hadoop.crypto.key.KeyProviderFactory.KEY_PROVIDER_PATH;


public class Client {
	private final Configuration conf = new YarnConfiguration();
	
	public void run(String[] args) throws Exception {
		YarnConfiguration conf = new YarnConfiguration();
		YarnClient yarnClient = YarnClient.createYarnClient();
		yarnClient.init(conf);
		yarnClient.start();
		
		String cryptopath = "";

		final String zonepaths = args[0];
		final String exclasspath = args[1];
		final String globalKMS = args.length == 2 ? "localhost:16000" : args[2];
		final String pluginURI = conf.get(NuCypherExtRpcServer.NUCYPHER_EXT_NAMENODE_SERVICE_RPC_ADDRESS_KEY,
				InetSocketAddress.createUnresolved(new URI(conf.get("fs.defaultFS")).getHost(),
						NuCypherExtRpcServer.DEFAULT_PORT).toString());

		String providers =  conf.get(KEY_PROVIDER_PATH);
		
		YarnClientApplication app = yarnClient.createApplication();
		
		ContainerLaunchContext amContainer = Records.newRecord(ContainerLaunchContext.class);

		amContainer.setCommands(
				Collections.singletonList(
				//"/usr/bin/java"+
				Environment.JAVA_HOME.$$() + "/bin/java" + 
				" -Xmx1024M"+
				" ApplicationMasterKMS"+
				" " + zonepaths +
				" " + exclasspath +
				" " + globalKMS +
				" " + providers +
				" " + pluginURI +
				" 1>" + ApplicationConstants.LOG_DIR_EXPANSION_VAR + "/stdout" + 
				" 2>" + ApplicationConstants.LOG_DIR_EXPANSION_VAR + "/stderr"));

		ApplicationSubmissionContext appContext = app.getApplicationSubmissionContext();
		ApplicationId appId = appContext.getApplicationId();

		LocalResource appMasterJar = Records.newRecord(LocalResource.class);
		// setupAppMasterJar(jarPath, appMasterJar);
		Map<String, LocalResource> localResources = new HashMap<>();
		//localResources.put("prkeyrotation.jar", appMasterJar);
		setupExtJar(exclasspath, localResources, appId.toString());
		amContainer.setLocalResources(localResources);
		
		Map<String, String> appMasterEnv = new HashMap<String, String>();
		setupAppMasterEnv(appMasterEnv, exclasspath);
		amContainer.setEnvironment(appMasterEnv);
		
		Resource capability = Records.newRecord(Resource.class);
		capability.setMemory(1024);
		capability.setVirtualCores(1);
		
		appContext.setApplicationName("prkeyrotation");
		appContext.setAMContainerSpec(amContainer);
		appContext.setResource(capability);
		appContext.setQueue("default");
		
		System.out.println("Submitting application "+appId);
		yarnClient.submitApplication(appContext);
		
		ApplicationReport appReport = yarnClient.getApplicationReport(appId);
		YarnApplicationState appState = appReport.getYarnApplicationState();
		while (appState != YarnApplicationState.FINISHED &&
				appState != YarnApplicationState.KILLED &&
				appState != YarnApplicationState.FAILED) {
			Thread.sleep(100);
			appReport = yarnClient.getApplicationReport(appId);
			appState = appReport.getYarnApplicationState();
		}
		
		System.out.println("Application " + appId + " finished with " +
								" state " + appState +
								" at " + appReport.getFinishTime());
		
		
	}
	
	private void setupAppMasterJar(Path jarPath, LocalResource appMasterJar) throws IOException {
		FileStatus jarStat = FileSystem.get(conf).getFileStatus(jarPath);
		appMasterJar.setResource(ConverterUtils.getYarnUrlFromPath(jarPath));
		appMasterJar.setSize(jarStat.getLen());
		appMasterJar.setTimestamp(jarStat.getModificationTime());
		appMasterJar.setType(LocalResourceType.FILE);
		appMasterJar.setVisibility(LocalResourceVisibility.APPLICATION);
	}

	private void setupExtJar(String exclasspath, Map<String, LocalResource> localResources, String appId) throws IOException {
		String[] excparray = exclasspath.split(",");
		FileSystem fs = FileSystem.get(conf);
		for (String cp: excparray) {
			addToLocalResources(fs, cp, Paths.get(cp).getFileName().toString(),  appId, localResources, null);
		}
	}
	private void addToLocalResources(FileSystem fs, String fileSrcPath,
																	 String fileDstPath, String appId, Map<String, LocalResource> localResources,
																	 String resources) throws IOException {
		String suffix =
				"prkeyrotation" + "/" + appId + "/" + fileDstPath;
		Path dst =
				new Path(fs.getHomeDirectory(), suffix);
		if (fileSrcPath == null) {
			FSDataOutputStream ostream = null;
			try {
				ostream = FileSystem
						.create(fs, dst, new FsPermission((short) 0710));
				ostream.writeUTF(resources);
			} finally {
				IOUtils.closeQuietly(ostream);
			}
		} else {
			fs.copyFromLocalFile(new Path(fileSrcPath), dst);
		}
		FileStatus scFileStatus = fs.getFileStatus(dst);
		LocalResource scRsrc =
				LocalResource.newInstance(
						ConverterUtils.getYarnUrlFromPath(dst),
						LocalResourceType.FILE, LocalResourceVisibility.APPLICATION,
						scFileStatus.getLen(), scFileStatus.getModificationTime());
		localResources.put(fileDstPath, scRsrc);
	}
	
	private void setupAppMasterEnv(Map<String, String> appMasterEnv, String exclasspath) {
		for (String c: conf.getStrings(
				YarnConfiguration.YARN_APPLICATION_CLASSPATH, 
				YarnConfiguration.DEFAULT_YARN_APPLICATION_CLASSPATH)) {
			Apps.addToEnvironment(appMasterEnv, Environment.CLASSPATH.name(), c.trim());
		}
		Apps.addToEnvironment(appMasterEnv, Environment.CLASSPATH.name(),
				Environment.PWD.$() + File.separator +"*");
		
		System.out.println("##env pwd:"+Environment.PWD.$());
		/*
		String[] excparray = exclasspath.split(",");
		for (String cp: excparray) {
			Apps.addToEnvironment(appMasterEnv, Environment.CLASSPATH.name(), cp);
		}*/
		
	}
	
	public static void main(String[] args) throws Exception {
		Client c = new Client();
		c.run(args);
	}
}
