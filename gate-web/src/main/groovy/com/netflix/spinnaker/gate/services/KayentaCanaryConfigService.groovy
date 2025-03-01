/*
 * Copyright 2017 Google, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.gate.services

import com.netflix.spinnaker.gate.services.internal.KayentaService
import com.netflix.spinnaker.kork.retrofit.Retrofit2SyncCall
import com.netflix.spinnaker.kork.retrofit.exceptions.SpinnakerServerException
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression
import org.springframework.stereotype.Component

import static com.netflix.spinnaker.gate.retrofit.UpstreamBadRequest.classifyError

@CompileStatic
@Component
@Slf4j
@ConditionalOnExpression('${services.kayenta.enabled:false} and ${services.kayenta.canary-config-store:false}')
class KayentaCanaryConfigService implements CanaryConfigService {

  @Autowired
  KayentaService kayentaService

  List getCanaryConfigs(String application, String configurationAccountName) {
    try {
      return Retrofit2SyncCall.execute(kayentaService.getCanaryConfigs(application, configurationAccountName))
    } catch (SpinnakerServerException e) {
      throw classifyError(e)
    }
  }

  Map getCanaryConfig(String id, String configurationAccountName) {
    try {
      return Retrofit2SyncCall.execute(kayentaService.getCanaryConfig(id, configurationAccountName))
    } catch (SpinnakerServerException e) {
      throw classifyError(e)
    }
  }

  Map createCanaryConfig(Map config, String configurationAccountName) {
    try {
      return Retrofit2SyncCall.execute(kayentaService.createCanaryConfig(config, configurationAccountName))
    } catch (SpinnakerServerException e) {
      throw classifyError(e)
    }
  }

  Map updateCanaryConfig(String id, Map config, String configurationAccountName) {
    try {
      return Retrofit2SyncCall.execute(kayentaService.updateCanaryConfig(id, config, configurationAccountName))
    } catch (SpinnakerServerException e) {
      throw classifyError(e)
    }
  }

  void deleteCanaryConfig(String id, String configurationAccountName) {
    try {
      Retrofit2SyncCall.execute(kayentaService.deleteCanaryConfig(id, configurationAccountName))
    } catch (SpinnakerServerException e) {
      throw classifyError(e)
    }
  }
}
