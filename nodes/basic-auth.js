function verifyBasicAuth({nodeMsg, rawAuthData, getUser, send, realm}) {
  const decodedAuthString = new Buffer(rawAuthData, "base64").toString();

  const authenticatingUser = decodedAuthString.split(":");
	const username = authenticatingUser[0];
  const password = authenticatingUser[1];

  try {
    const configuredUser = getUser(username);
    if (password === configuredUser.password) {
      handleSuccessfulAuth({
        send,
        nodeMsg,
        realm
      });
    } else {
      handleFailedAuthAttempt({
        send,
        nodeMsg,
        errorMsg: `Invalid password for username "${username}"`,
        username,
        realm
      });
    }
  } catch (error) {
    handleFailedAuthAttempt({
      send,
      nodeMsg,
      errorMsg: `Invalid username "${username}"`,
      username,
      realm
    });
  }
}

const requestAuth = ({nodeMsg, realm}) => {
	const res = nodeMsg.res._res || nodeMsg.res;

	res.set("WWW-Authenticate", `Basic realm="${realm}"`);
	res.type("text/plain");
  res.status(401).send("401 Unauthorized");
}

const handleSuccessfulAuth = ({send, nodeMsg}) => {
  send([nodeMsg, null]);
}

const handleFailedAuthAttempt = ({send, nodeMsg, errorMsg, username, realm}) => {
  requestAuth({
    nodeMsg,
    realm
  });

  send([null, {
    payload: errorMsg,
    username
  }]);
}

module.exports = function(RED) {
	"use strict";

	function BasicAuthNode(config) {
    const node = this;
    RED.nodes.createNode(node, config);

    // Config data
		const realm = config.realm.trim();
		const username = config.username.trim();
    const password = config.password;

    // Configured user
    const user = {
      username,
      password
    }

		const getUser = (username) => {
      if (user.username === username) {
        return user;
      } else {
        throw new Error();
      }
    }

		this.on('input', function (nodeMsg, send, done) {
      // Compatibility for older version of Node-RED
      send = send || function() {
        node.send.apply(node, arguments);
      }

      // Get authentication header and type, if it exists
      const authHeader = nodeMsg.req.get("Authorization");
      const authHeaderMatches = authHeader ? authHeader.match(/^(\w+) (.*)$/) : [];

			if (authHeader && authHeaderMatches[1] === "Basic") {
        // Get the raw authentication data string
        const rawAuthData = authHeaderMatches[2];

        if (rawAuthData) {
          verifyBasicAuth({
            nodeMsg,
            rawAuthData,
            getUser,
            send,
            realm
          });
        } else {
          requestAuth({
            nodeMsg,
            realm,
          });
        }
      } else {
        requestAuth({
          nodeMsg,
          realm,
        });
      };

      if (done) {
        done();
      }
    });
	};

	RED.nodes.registerType("node-red-contrib-basicauth", BasicAuthNode);
};
