package eu.ngpaas.conn.core;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Iterables;
import eu.ngpaas.pmLib.*;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Service;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.glassfish.jersey.jaxb.internal.XmlJaxbElementProvider;
import org.onlab.osgi.DefaultServiceDirectory;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.HostId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.Key;
import org.slf4j.Logger;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true)
@Service
public class ConnectivityManager implements PolicyService {
    //Instantiate the required services
    private CoreService coreService = DefaultServiceDirectory.getService(CoreService.class);

    private final Logger log = getLogger(getClass());
    private WebTarget RESTtarget = ClientBuilder.newClient(new ClientConfig())
            .register(HttpAuthenticationFeature.basic("onos", "rocks"))
            .target(UriBuilder.fromUri("http://localhost:8181/onos/policymanager").build());

    @Activate
    public void activate() {
        log.info("Connectivity Policy started");
        Response response = RESTtarget.path("policytype/register/connectivity")
                .request(MediaType.APPLICATION_JSON)
                .put(Entity.text(""));
        if (response.getStatus() != Response.Status.OK.getStatusCode()){
            log.info("Policy Framework not found.");
            throw new RuntimeException();
        }
        log.info("Connectivity Policy type successfully registered.");

    }

    @Deactivate
    protected void deactivate() {
        log.info("Connectivity Policy stopping");
        log.info("De-registering Conectivity Policy from PM");
        Response response = RESTtarget.path("policytype/deregister/connectivity").request(MediaType.APPLICATION_JSON).delete();
        String prsJSON = response.readEntity(String.class);
        log.info(prsJSON);
        PolicyRules prs = parsePolicyRules(prsJSON);
        for (PolicyRule pr:prs.getPolicyRules()) {
            remove(pr);
        }
        log.info("Connectivity Policies Deleted");
    }


    public PolicyRules parsePolicyRules(String json) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        PolicyRules policyRules = null;
        try {
            policyRules = mapper.readValue(json, PolicyRules.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return policyRules;
    }

    @Override
    public SimpleResponse formalValidation(PolicyRule pr) {
        SimpleResponse restResponse;

        List<String> supported_conds = Arrays.asList("src_ip","dst_ip");
        List<String> supported_actions = Arrays.asList("connect");

        log.info(pr.toJSONString());

        for (CopyOnWriteArrayList<PolicyCondition> clause: pr.getPolicyConditions()){
            log.info("Clause size: " + String.valueOf(clause.size()));
            //if (clause.size() != 2) return new SimpleResponse("Formal error: A pair of source and destination addresses must be provided.", false);
            for (PolicyCondition pc: clause){
                if (!supported_conds.contains(pc.getPolicyVariable())){
                    restResponse = new SimpleResponse("Formal error: Parameter " + pc.getPolicyVariable() + " invalid.", false);
                    return restResponse;
                }
            }
        }

        if (pr.getPolicyActions().size()>1) return new SimpleResponse("Formal error: Only one action is supported", false);
        if (!supported_actions.contains(pr.getPolicyActions().get(0).getPolicyVariable()) || !pr.getPolicyActions().get(0).getPolicyValue().equalsIgnoreCase("true"))
            return new SimpleResponse("Formal error: Incorrect action", false);

        return new SimpleResponse("Formally validated.", true);
    }

    @Override
    public SimpleResponse contextValidation(PolicyRule pr) {
        for(CopyOnWriteArrayList<PolicyCondition> clause: pr.getPolicyConditions()){
            if (!conditionsContextValidator(clause) ||
                    !actionsContextValidation(clause)){
                return new SimpleResponse("Policy failed at context validation", false);
            }
        }
        return new SimpleResponse("Policy context validated", true);
    }

    //Check that all the hosts exist
    private Boolean conditionsContextValidator(CopyOnWriteArrayList<PolicyCondition> pcs){
        for (PolicyCondition pc: pcs){
            HostService hostService = DefaultServiceDirectory.getService(HostService.class);
            if(hostService.getHostsByIp(IpAddress.valueOf(pc.getPolicyValue())).isEmpty()){
                return false;
            }
        }
        return true;
    }

    //Check that natted IP is not being used
    private Boolean actionsContextValidation(CopyOnWriteArrayList<PolicyCondition> pcs){
        return true;
    }

    @Override
    public void enforce(PolicyRule pr) {
        PolicyAction pa = pr.getPolicyActions().get(0);
        IntentService intentService = DefaultServiceDirectory.getService(IntentService.class);
        ApplicationId applicationId = coreService.registerApplication("Connectivity"+String.valueOf(pr.getId()));
        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()){
            HostToHostIntent h2hi = getIntent(clause, pa,applicationId);
            intentService.submit(h2hi);
        }

    }

    private HostToHostIntent getIntent(CopyOnWriteArrayList<PolicyCondition> pcs, PolicyAction pa, ApplicationId applicationId){

        //Instantiate the necessary services
        HostService hostService = DefaultServiceDirectory.getService(HostService.class);
        CoreService coreService = DefaultServiceDirectory.getService(CoreService.class);

        //Get the application ID of the policyManager
        MacAddress srcmac = null;
        MacAddress dstmac = null;

        //Get the source and destination mac addresses of the hosts two connect.
        for (PolicyCondition pc:pcs){
            if (pc.getPolicyVariable().equalsIgnoreCase("src_mac")){
                srcmac = Iterables.get(hostService.getHostsByIp(IpAddress.valueOf(pc.getPolicyValue())),0).mac();
            }
            else{
                dstmac = Iterables.get(hostService.getHostsByIp(IpAddress.valueOf(pc.getPolicyValue())),0).mac();
            }
        }

        //Translate the mac addresses to HostIds
        HostId src = HostId.hostId(srcmac);
        HostId dst = HostId.hostId(dstmac);

        //Create and submit the host to host Intent
        TrafficSelector ts = DefaultTrafficSelector.emptySelector();
        TrafficTreatment tt = DefaultTrafficTreatment.emptyTreatment();
        Key key;

        if (src.toString().compareTo(dst.toString())<0) key = Key.of(src.toString() + dst.toString(),applicationId);
        else key = Key.of(dst.toString() + src.toString(),applicationId);

        return HostToHostIntent.builder()
                .appId(applicationId)
                .key(key)
                .one(src)
                .two(dst)
                .selector(ts)
                .treatment(tt)
                .build();
    }

    @Override
    public void remove(PolicyRule pr) {
        PolicyAction pa = pr.getPolicyActions().get(0);
        IntentService intentService = DefaultServiceDirectory.getService(IntentService.class);
        ApplicationId applicationId = coreService.getAppId("Connectivity"+String.valueOf(pr.getId()));
        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()){
            HostToHostIntent h2hi = getIntent(clause, pa, applicationId);
            intentService.withdraw(h2hi);
        }
    }

    @Override
    public ForwardingObjectiveList getFlowRules(PolicyRule policyRule) {
        return null;
    }
}
