# Testing using a local PIN server

It's possible to run the tests by spinning up a local copy of the PIN server
and setting a couple of environment variables:

  1) generate the public key of the PIN server by following [these instructions](https://github.com/Blockstream/blind_pin_server#to-generate-a-new-key);

  2) set the `$PIN_SERVER_PUBLIC_KEY` environment variable to the value of the
  public key generated in the previous step;

  3) spin un the server by building and running its docker image;

  4) set the `$PIN_SERVER_URL` to the URL of the locally running PIN server.
  For example if it was launched on port `8096` this would be
  `http://127.0.0.1:8096`.
