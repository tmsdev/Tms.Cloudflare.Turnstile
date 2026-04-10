<?php
namespace Tms\Cloudflare\Turnstile\Validation\Validator;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Client\Browser;
use Neos\Flow\Http\Client\CurlEngine;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Validation\Validator\AbstractValidator;
use Psr\Log\LoggerInterface;

/**
 * Turnstile validator
 */
class TurnstileValidator extends AbstractValidator
{
    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var boolean
     */
    protected $acceptsEmptyValues = false;

    /**
     * @var array
     */
    protected $supportedOptions = [
        'endpoint' => ['', 'Turnstile API endpoint', 'string', true],
        'secretKey' => ['', 'Secret key of your Turnstile site', 'string', true]
    ];

    /**
     * @param mixed $value The value that should be validated
     *
     * @return void
     * @throws \Neos\Flow\Validation\Exception\InvalidValidationOptionsException
     */
    protected function isValid($value)
    {
        if (!is_string($value) || empty($value)) {
            $this->addError('The captcha challenge failed.', 1676890456);
            $this->logger->error('No value was given for turnstile validator', LogEnvironment::fromMethodName(__METHOD__));
            return;
        }

        $requestEngine = new CurlEngine();
        $requestEngine->setOption(CURLOPT_TIMEOUT, 60);

        $browser = new Browser();
        $browser->setRequestEngine($requestEngine);

        $arguments['secret'] = $this->getOptions()['secretKey'];
        $arguments['response'] = $value;

        try {
            $response = $browser->request($this->getOptions()['endpoint'], 'POST', [], [], [], http_build_query($arguments));
            $responseContent = json_decode($response->getBody()->getContents(), true);
            $this->logger->debug(json_encode($responseContent), LogEnvironment::fromMethodName(__METHOD__));

            if (!$responseContent['success']) {
                $this->logger->warning('Turnstile validation did not succeed. Response: '. json_encode($responseContent), LogEnvironment::fromMethodName(__METHOD__));
                $this->addError('We could not identify you as a human. Please try again.', 1676890456);
            }
        } catch (\Exception $e) {
            $this->logger->error('Turnstile validation failed.' . $e->getMessage(), LogEnvironment::fromMethodName(__METHOD__));
            $this->addError('We could not identify you as a human. Please try again.', 1676890456);
        }

        $this->logger->info('Turnstile validation succeeded.', LogEnvironment::fromMethodName(__METHOD__));
    }
}
